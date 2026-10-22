# Legacy v10 bridge

`tensorwire.extensions.legacy_v10` lets old and new nodes work together while a
subnet migrates from bittensor v10 (spec 8.11). It is **opt-in and time-boxed**
in both directions, and it never imports bittensor v10 ([ADR-0008](../adr/0008-reimplement-v10-wire-format.md)).

| | v10 miner (old Axon) | TensorWire miner |
|---|---|---|
| **v10 validator (old Dendrite)** | unchanged | server side: `TW_LEGACY_V10_UNTIL` |
| **TensorWire validator** | client side: `TW_LEGACY_V10_CLIENT=auto` | btauth/1 |

Both settings take an end date at most **180 days** after the process starts.
A process refuses to start with a date that is today or in the past. A process
that keeps running stops using v10 on that date: the miner answers v10 requests
with 410 `tw.legacy_disabled`, and the validator stops sending v10.

## The wire format (`wire.py`)

Built from bytes captured from a real `bittensor==10.5.0` Dendrite and Axon
(`conformance/vectors/legacy_v10.json`). The full description is spec 8.11.1. In
short:

- **Request:** `POST http://{ip}:{port}/{SynapseName}`. The body is the whole Synapse
  as JSON. The headers are `bt_header_axon_*`, `bt_header_dendrite_*`, one
  `bt_header_input_obj_<field>` per required field (base64 of the JSON of a
  *default* value of the field's type), and `computed_body_hash`.
- **Body hash:** `sha3_256_hex(concat(sha3_256_hex(str(value)) for each hash field))`,
  where the values come from `model_dump()` of the parsed model, never from the
  JSON text. Hash fields are listed in `required_hash_fields`. A `ClassVar` is
  hashed in declared order. The deprecated pydantic-field style is hashed in
  model order. With no hash fields, the hash is `sha3_256("")`.
- **Signature:** sr25519, by the validator hotkey, over
  `nonce.sender.receiver.uuid.body_hash`. The receiver is the miner's own hotkey.
- **Response:** the HTTP status equals `bt_header_axon_status_code`. On success
  the body is the whole Synapse; on failure it is `{"message": ...}`.
- **v10 marker:** a v10 Axon answers a btauth/1 request with HTTP 500 and a
  `bt_header_axon_status_code` header (`wire.is_v10_response`).

| Function | Purpose |
|---|---|
| `hash_fields(cls)`, `body_hash(synapse)`, `hash_values(values)` | the 8.11.1 hash; `compat.Synapse.body_hash` uses it |
| `check_synapse_class(cls)` | startup check: a pydantic model whose hash fields exist |
| `parse_request_headers(headers)` | shape-checked v10 headers (`WireError` otherwise) |
| `decode_request_body(cls, body)` | `json.loads` then `cls.model_validate`, the parse a v10 Axon does |
| `encode_request(...)` | what a v10 Dendrite sends (sr25519 signers only) |
| `encode_response(...)`, `decode_response(...)` | v10-shaped answers |
| `request_message`, `response_message` | the signed strings |
| `is_legacy_request(headers)`, `is_v10_response(status, headers)` | detection |

## Server side: v10 validators → TensorWire miner (`server.py`)

`LegacyServer` is built by the miner at startup when `TW_LEGACY_V10_UNTIL` is
set. The miner pipeline calls it at step [6] for requests that
`LegacyServer.is_legacy(headers)` recognises (a `bt_header_dendrite_signature`
header and no `X-Bittensor-Signature`). Routes declared with
`legacy_synapse=` (or `legacy_body_hash=`) accept them; on other routes a v10
request is rejected.

`verify(headers, body, synapse_cls=..., body_hash=...)` runs in a worker thread,
in this order. Any failure is 401 `tw.legacy_auth_failed`, unless the line says
otherwise.

1. End date. Past it: 410 `tw.legacy_disabled`.
2. Header shape. The sender must be a prefix-42 SS58 address, the nonce plain
   digits, the uuid letters, digits and dashes, the signature `0x` + 128 hex,
   and the body hash 64 lowercase hex. Duplicate v10 headers are rejected.
3. Freshness. The kit's window: at most `TW_AUTH_MAX_AGE_S` old and at most
   `TW_AUTH_ALLOWED_SKEW_S` in the future. v10 has no upper bound. The v10 rules
   also apply: the first nonce per `(sender, uuid)` must be newer than
   `now − 4 s − timeout`, and later nonces must be strictly greater.
4. The body is parsed into the Synapse class, and the hash is computed from the
   model values and compared with `computed_body_hash`.
5. The sr25519 signature is checked against the miner's own hotkey.
6. The replay store: `check_and_store("legacy_v10:" + sender, nonce)`. A store
   that is down answers 503 `tw.replay_store_unavailable`.

The caller policy, per-hotkey rate limit and handler then run as for
btauth/1. The handler's Synapse has `dendrite` set from the **verified**
headers and `axon` set to this miner, whatever the body claimed.

`respond(request_headers, request=..., status=..., synapse=..., error=...,
process_time_s=..., raw_body=None)` builds every answer in v10 shape. Answers to
verified requests (200, and 403 / 429 / 422 / 500 / 504 raised after
verification) carry the v10 axon signature, over
`axon_nonce.dendrite_hotkey.miner_hotkey.axon_uuid`. Answers to rejected
requests are not signed, so unauthenticated input never makes the miner sign
anything. v10 Dendrites do not check that signature.

## Client side: TensorWire validator → v10 miners (`client.py`)

`LegacyClient(signer)` sends one v10 request per call:
`query(http, neuron, synapse, timeout_s=..., max_response_bytes=...) -> LegacyResult`.
It uses a fresh, strictly increasing nonce and a uuid4 that is fixed per
instance (v10's uuid1 embeds the host MAC). The signer must be sr25519. It never
raises for one miner's failure: `error_code` is `tw.timeout`, `tw.connect_error`,
`tw.response_too_large`, `tw.invalid_response`, `tw.no_axon` or `tw.http_<status>`.

`ProtocolSelector(protocol_tag, until=...)` makes the per-miner choice of spec
8.11.3. `ValidatorClient(legacy=..., selector=...)` calls it:

- `choose(neuron)` returns btauth/1 when the on-chain `axon_protocol` equals
  `TW_PROTOCOL_TAG` (and then never falls back), when the hotkey has given a
  verified btauth/1 answer, or when nothing is known yet. It returns v10 for a
  hotkey remembered as v10.
- `after_btauth(neuron, status=, headers=, verified=)` returns True when the
  btauth/1 answer carries the v10 marker. The caller then sends one v10 attempt
  at once, and the hotkey is remembered as v10. A `verified=True` answer (a valid
  twresp/1 signature) makes the hotkey btauth/1-only until it changes: **no
  downgrade**. Unverified answers without the marker, such as a proxy's 502,
  change nothing.
- `reprobe()` is called by the validator loop once per tempo. It forgets the v10
  memory, so upgraded miners move to btauth/1 without a restart. `forget(hotkey)`
  clears a hotkey whose UID changed hands.

v10 answers are reported as `MinerResult(protocol="v10", response_verified=False)`.

## What v10 does not protect

The v10 signature covers the sender, receiver, nonce and the hash fields only.
It does not cover the HTTP method, the path, fields outside
`required_hash_fields` (vector N8), or any response. Fields that matter for
scoring must be listed in `required_hash_fields`. `tensorwire migrate scan`
flags Synapses with an empty or partial list.

## Testing

- `tests/migration/test_legacy_v10_bridge_vectors.py`: every captured request
  replayed through `LegacyServer`, `encode_request` checked against the real v10
  Dendrite's bytes, and answers checked against the real v10 Axon's.
- `tests/migration/test_legacy_v10_live.py`: interop with a real 10.5.0 Axon and
  Dendrite through `scripts/v10_peer.py`, no chain needed.
- `tests/integration/test_legacy_v10_bridge.py`: integration tests 12 and 13.
- `tests/localnet/test_mixed_fleet_localnet.py`: the four-cell mixed fleet of
  spec 13.8 (`just mixed-fleet`), described in
  `examples/migrations/template-v10-to-v11/mixed-fleet.yml`.
