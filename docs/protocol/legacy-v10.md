# Legacy v10 bridge

`tensorwire.extensions.legacy_v10` lets old and new nodes work together while a
subnet migrates from bittensor v10 (spec 8.11). It is **opt-in and time-boxed**
in both directions, and it never imports bittensor v10 ([ADR-0008](../adr/0008-reimplement-v10-wire-format.md)).

| | v10 miner (old Axon) | TensorWire miner |
|---|---|---|
| **v10 validator (old Dendrite)** | unchanged | server side: `TW_LEGACY_V10_UNTIL` |
| **TensorWire validator** | client side: `TW_LEGACY_V10_CLIENT=auto` | btauth/1 |

Both directions take an end date `<date>` (`TW_LEGACY_V10_UNTIL`,
`TW_LEGACY_V10_CLIENT_UNTIL`). v10 is used **through the day before `<date>`
(UTC)**; from `<date>` on, the miner answers v10 requests with 410
`tw.legacy_disabled` and the validator stops sending v10. A running process and
a restarted one behave the same: a process refuses to start when `<date>` is
today or earlier, or more than **180 days** away. There is no "forever" option.

The validator side also refuses to start (`StartupError` naming
`TW_LEGACY_V10_CLIENT` and `TW_LEGACY_V10_CLIENT_UNTIL`) when `auto` is set with
an ed25519 hotkey: v10 Axons verify sr25519 signatures only.

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
| `encode_response(...)`, `decode_response(...)` | v10-shaped answers (`NonFiniteAnswer` for a 200 that JSON would change) |
| `non_finite_field(synapse)` | the first field JSON would turn into `null`, or `None` |
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

1. End date. On or after `<date>` (UTC): 410 `tw.legacy_disabled`.
2. Header shape. The sender must be a prefix-42 SS58 address, the nonce plain
   digits, the uuid letters, digits and dashes, the signature `0x` + 128 hex,
   and the body hash 64 lowercase hex. Duplicate v10 headers are rejected.
3. Freshness. The kit's window: at most `TW_AUTH_MAX_AGE_S` old and at most
   `TW_AUTH_ALLOWED_SKEW_S` in the future. v10 has no upper bound. The v10 rules
   also apply: the first nonce per `(sender, uuid)` must be newer than
   `now − 4 s − timeout`, and later nonces must be strictly greater.
4. The body is parsed into the Synapse class, and the hash is computed from the
   model values and compared with `computed_body_hash`. A body that does not
   parse into the Synapse (not JSON, wrong types, too deeply nested) is also
   401 `tw.legacy_auth_failed`, as is a hash mismatch. (A v10 Axon answers
   500 for both.)
5. The sr25519 signature is checked against the miner's own hotkey.
6. The replay store: `check_and_store("legacy_v10:" + sender, nonce)`. A store
   that is down answers 503 `tw.replay_store_unavailable`.

The caller policy, per-hotkey rate limit and handler then run as for
btauth/1. The handler's Synapse has `dendrite` set from the **verified**
headers and `axon` set to this miner, whatever the body claimed.

`respond(request_headers, request=..., status=..., synapse=..., error=...,
process_time_s=..., raw_body=None)` builds every answer in v10 shape.

**Axon signature scope (spec 8.11.2).** Only answers to **verified** requests
carry the v10 axon signature: 200, and 403 / 429 / 422 / 500 / 504 raised after
verification. It is made with the **miner's own hotkey**, over
`axon_nonce.dendrite_hotkey.miner_hotkey.axon_uuid`. (A v10 Axon puts the
request's `bt_header_axon_hotkey` in that string; the kit never signs a hotkey
it did not verify.) 401, 410 and the pre-authentication answers (per-IP 429,
413, 503 `tw.metagraph_stale` / `tw.replay_store_unavailable`) are unsigned, so
unauthenticated input never makes the miner sign anything. v10 Dendrites check
neither the signature nor its absence; it is there for parity and audit.

**Non-finite floats in answers (spec 8.11.2).** A 200 answer is the handler's
Synapse dumped in pydantic's JSON mode. A `float` field keeps `inf` / `nan`
(sent as `Infinity` / `NaN`, as a v10 Dendrite sends requests, and parsed back
unchanged), but a value held under `Any` (`dict[str, Any]`, `list[Any]`, ...)
would become `null`. The kit never changes an answer silently: such an answer is
500 `tw.handler_error`, and the `legacy_non_finite_answer` log line names the
field (`meta.r`, `w[0]`, `by_uid[7]`). `wire.non_finite_field(synapse)` runs the
same check. (A real v10 Axon fails on any non-finite float.)

Every inbound and outbound v10 call is counted in
`tw_legacy_v10_requests_total{direction}`; `tw_legacy_v10_days_remaining{direction}`
is computed from the end date at every scrape (alert below 14 days).

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
  clears a hotkey whose UID changed hands, and a hotkey whose signed protocol tag
  moved away from the kit's (below).

v10 answers are reported as `MinerResult(protocol="v10", response_verified=False)`.

### Rollback through the signed protocol tag (spec 8.11.3 step 5, decision D16)

"No downgrade" would otherwise leave a miner that rolls back to its v10 release
unreachable from every running TensorWire validator until that validator
restarts: the validator remembers the hotkey as btauth/1-only, keeps sending
btauth/1, and the v10 Axon answers 500. The kit lifts that memory on one signal
an on-path attacker cannot forge, the hotkey's on-chain axon `protocol` tag. It
is written by a `ServeAxon` extrinsic signed by the miner's own hotkey; the kit
publishes `TW_PROTOCOL_TAG` (default 87) and v10's `serve_axon` publishes 4.

- At each metagraph refresh the validator compares every hotkey's
  `axon_protocol` with the previous snapshot. When it **was** `TW_PROTOCOL_TAG`
  and now is any other value, it calls `ProtocolSelector.forget(hotkey)` and
  logs `legacy_v10_protocol_tag_changed` at INFO with the hotkey prefix, the old
  and the new tag.
- The next query to that hotkey follows steps 1–2 again: btauth/1 first, and one
  v10 attempt when the answer carries the v10 marker. A miner that rolled back is
  reached over v10 without a validator restart (runbook stage 2 rollback, spec
  10b.5). If it later re-publishes the kit's tag, step 1 applies again
  immediately.
- `ProtocolSelector` itself is unchanged: the trigger lives in the validator's
  refresh path (Engineer A), next to the `forget()` on a hotkey change.

Limits:

- Only the transition **from** `TW_PROTOCOL_TAG` counts. A v10-shaped answer on
  its own, with no tag change, still never downgrades a btauth/1 hotkey. A miner
  that answered btauth/1 but never published the kit's tag (for example, it runs
  the kit with its own `ServeAxon` code) stays btauth/1-only until the validator
  restarts, as before D16.
- The switch happens at the validator's **first refresh after** the new axon
  info is on chain (`TW_METAGRAPH_REFRESH_S`, default 120 s). The miner's
  `ServeAxon` is subject to the subnet's `serving_rate_limit` (50 blocks by
  default, 10 min on 12 s blocks), so a miner that served recently may have to
  wait before it can publish the rollback at all. Until then the validator
  keeps sending btauth/1 to it and scores those queries as failures.
- Anyone who controls the miner's hotkey can move the tag, but such a party can
  already serve any answer as that miner; the tag adds no new power.

Checked on localnet by `scripts/rollout_walkthrough.py` (stage 2 rollback: the
running validator reaches the rolled-back miner over v10, `n_v10=1`, logs
`legacy_v10_protocol_tag_changed`, same process) and by integration test 13.

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
