# Security

What TensorWire defends against, how, what you must still do yourself, and
the test that proves each default. The reference is spec Section 16. To report
a vulnerability, see `SECURITY.md` at the repository root.

## Threat model

| Actor | Can do | Main defences |
|---|---|---|
| Internet scanner / DDoS | Send arbitrary bytes to the miner's public IP (it is on chain) | Per-IP rate limit first, request-read deadline, header and body caps, concurrency limit, firewall guidance |
| Registered non-validator hotkey | Send validly signed requests | Caller policy: registered + validator permit (+ optional minimum stake) |
| Malicious miner | Forward a validator's request to another miner, replay requests, return forged or copied answers | Receiver binding, replay store, `twresp/1` response signatures, timelock option (Phase 4) |
| On-path attacker | Read or change plain HTTP traffic | Signed requests and responses (integrity), TLS for confidentiality (Phase 4) |
| Malicious validator | Leak a miner's answer to another miner before scoring | Sealed (timelocked) responses: nobody can read them before the drand round, the validator included (spec 8.10, [timelock.md](timelock.md)) |
| Supply-chain attacker | Poison a release or a dependency | Locked dependencies, `just audit`, signed releases (spec 18) |
| Local attacker on the miner host | Read the hotkey file | Out of scope for code: host hardening below |

## The traps, and how the kit handles each (spec 16.1)

| # | Trap | Default | Proven by |
|---|---|---|---|
| 1 | Replay across processes or hosts | Redis replay store required when `TW_WORKERS > 1` or `TW_INSTANCE_COUNT > 1`; the miner refuses to start with a per-process store; a Redis outage fails closed (503 `tw.replay_store_unavailable`) | `tests/integration/test_miner_process.py`, `test_redis_nonce_store.py`, `tests/unit/test_nonce_store.py`; replay storm across 2 workers never served twice: `tests/abuse/test_abuse.py::test_replay_storm` |
| 2 | Hashing a re-serialised body | Signatures are verified on the raw bytes before parsing; handlers only see verified bytes | integration test 1 (`test_miner_requests.py`), `tests/property/test_auth_properties.py` |
| 3 | Decoded path used as the signed target | The raw request target (`raw_path` + query) is what is verified | `tests/unit/test_miner_app.py`, property tests; conformance P4 (Phase 5) |
| 4 | Clock drift and clock steps | NTP check at startup and on a schedule; `/readyz` reports `clock_skew`; `tensorwire doctor` checks it. Replay stores keep at least `2 × (max_age + allowed_skew)`; the memory store forgets a pair only when both clocks agree; a backwards wall-clock step larger than the margin fails closed for `retention` seconds (503 `tw.replay_store_unavailable`, `/readyz` `clock_step`), D21 | `tests/unit/test_clock_guard.py`, `tests/integration/test_miner_lifecycle.py`; D21: `tests/unit/test_clock_step.py` (memory and Redis, injected clocks), `tests/integration/test_redis_nonce_store.py` (real Redis), `tests/integration/test_miner_pipeline.py::test_backwards_clock_step_fails_closed`, `tests/unit/test_config.py::test_nonce_retention_covers_twice_the_window` |
| 5 | Unbound receiver | Miners always require `X-Bittensor-Receiver` to be their own hotkey; the signer refuses an empty receiver | `tests/unit/test_signer.py`, `tests/unit/test_verifier.py` |
| 6 | Transport retries resend a signed request | The validator client uses `retries=0`; its own retries sign afresh with a new nonce | `tests/unit/test_validator_client.py::test_the_default_transport_never_retries`, `::test_each_attempt_is_signed_afresh_and_bound_to_the_miner` |
| 7 | Authenticated is not authorised | Strict caller policy (registered + permit) by default; staged metagraph staleness (below) | `tests/unit/test_policy.py`, `tests/unit/test_chain_metagraph_cache.py`, `tests/integration/test_miner_requests.py` |
| 8 | Flooding, oversized bodies | Per-IP limit (outermost) → body cap → verification (thread pool, bounded) → per-hotkey limit; streams: the same pipeline before the first byte, then whole-stream, byte and idle limits on both sides and at most `TW_STREAM_MAX_PER_CALLER` (default 16) open streams per caller hotkey per miner process (spec 9.2, D29, D36); request-read deadline, 16 KiB / 100-field header cap; the sender address must be exactly 48 characters before any base58 decoding (D19) | `tests/abuse/test_abuse.py` (all five attacks, `just abuse`), `tests/abuse/test_stream_abuse.py` (slow drip, endless stream, unread streams), `tests/integration/test_miner_protocol.py`, `tests/unit/test_ratelimit.py`, `tests/unit/test_body_limit.py`; sender bound: `tests/unit/test_crypto.py::test_huge_sender_costs_no_decode_work`, `::test_length_is_checked_before_base58_decoding`, `tests/unit/test_verifier.py::test_huge_sender_is_refused_before_decoding` |
| 9 | Unsigned responses | `twresp/1` on by default; the validator scores a bad or missing signature as a failure. Streams end with a signed `tw-end` trailer over the digest of every chunk; chunks are handed out as unverified until it verifies, and a missing, invalid or duplicate trailer, data after it or a count mismatch fails the whole stream (spec 9.2) | `tests/unit/test_response_sig.py`, `tests/property/test_response_sig_properties.py`, integration tests 10 and 11 (`tests/integration/test_stream_routes.py`), `tests/property/test_streaming_properties.py` |
| 10 | Public miner IPs | Documented: firewall, optional proxy, only the miner port exposed; metrics bind to 127.0.0.1 by default. Optional TLS (spec 16.3, D31): uvicorn or a reverse proxy, the key published with `ServeAxonTls`; validators with `https-if-tls-published` pin it against the chain and never fall back to HTTP for a miner that published one ([TLS](#tls-spec-163-d31-adr-0011)) | this page ("What you still have to do"), `docs/miner-guide.md`, `tests/integration/test_tls_modes.py`, `tests/integration/test_miner_tls.py`, `tests/property/test_tls_properties.py`, `tests/localnet/test_tls_localnet.py` |
| 11 | Answer copying / leaking | Timelock extension (opt-in, spec 8.10, D30): sealed challenges and sealed responses, bound to their miner (a copied sealed answer fails its binding check); `bt.timelock` only through the chain gateway; process-wide drand limiter, bounded retries and deadlines, drand trouble is `tw.timelock_unavailable` (never a hang); stale challenges refused ([timelock.md](timelock.md)) | `tests/unit/test_timelock.py`, `tests/property/test_timelock_properties.py`, `tests/integration/test_timelock_round.py`, `tests/localnet/test_timelock_localnet.py` (sealed challenge + sealed response on localnet) |
| 12 | Weak legacy bridge, both directions | Opt-in; mandatory end dates on both sides (at most 180 days); kit freshness, replay store and caller policy on inbound v10; no downgrade after a miner answered over btauth/1, except when its own signed `ServeAxon` moves its protocol tag away from the kit's (D16); `migrate scan` flags unhashed Synapse fields; traffic counters | `tests/integration/test_legacy_v10_bridge.py` (12, 13), `test_miner_legacy_hook.py`, `test_validator_protocol_tag.py`, `tests/migration/test_migrate_scan.py` (TWM100/TWM101) |
| 19 | Compat hooks weakening security | `blacklist_fn` runs after the caller policy and can only narrow; a custom `verify_fn` is refused at startup | `tests/integration/test_compat_layer.py::test_15_blacklist_cannot_widen_access`, `tests/unit/test_compat.py` |
| 13 | Coldkey on the server | The kit never opens `wallet.coldkey`; a readable unencrypted coldkey stops startup (`TW_REFUSE_IF_COLDKEY_PRESENT=1`) | `tests/integration/test_miner_lifecycle.py`, `tests/integration/test_validator_runner.py`, `tests/unit/test_auth_keys.py` |
| 14 | Supply chain | `uv.lock`, `just audit` (pip-audit), signed releases (spec 18) | `just audit` |
| 15 | Nonce collisions on coarse clocks | Monotonic nanosecond nonce | `tests/unit/test_signer.py` |
| 16 | Redirects breaking target binding / SSRF | `follow_redirects=False`; private and loopback axons rejected unless `TW_ALLOW_PRIVATE_AXONS=1` (localnet) | `tests/unit/test_validator_client.py::test_redirects_are_not_followed`, `tests/unit/test_chain_axon.py` |
| 17 | Error messages leaking internals | Fixed public messages per `tw.*` code; request IDs for correlation; handler exceptions are logged, never sent | `tests/unit/test_errors.py`, `tests/integration/test_miner_requests.py` |
| 18 | Sidecar abuse | `tensorwire sidecar` binds `127.0.0.1` / `::1` only (anything else needs `TW_SIDECAR_UNSAFE_BIND=1`: WARNING + `tw_unsafe_settings_active`); every request needs the bearer token from an owner-only file (generated 0600, never logged, constant-time compare, a repeated header never matches; 401 `tw.sidecar_unauthorized`); `POST /v1/serve-axon` only for the configured netuid, addresses through `parse_axon`, strict bodies, each write sent once; no weight setting. The TS / Go / Rust clients refuse a non-loopback URL unless told otherwise, check the sidecar runs with the miner's hotkey, parse every answer strictly and fail closed (arbitrary JSON never admits a caller), and apply the staleness stages locally ([sidecar.md](sidecar.md)) | `tests/unit/test_sidecar.py`, `tests/property/test_sidecar_properties.py`; clients: `typescript/test/sidecar.test.ts`, `go/sidecar/sidecar_test.go` (+ `FuzzParseSnapshot`, `FuzzParseDecision`), `rust/tests/sidecar.rs` (+ `cargo fuzz` target `sidecar`); live: `conformance/interop/sidecar_check.py`, `run_matrix.py` |

## Secure defaults (spec 16.2)

A setting that weakens a row above is either named `TW_UNSAFE_*` or clearly
bounded (`TW_LEGACY_V10_UNTIL`, `TW_LEGACY_V10_CLIENT_UNTIL`). Every active
weakening setting is logged at WARNING at startup and exported as
`tw_unsafe_settings_active{name}`, on miners and validators
(`tests/integration/test_miner_lifecycle.py`, `tests/unit/test_observability.py`).
`TW_ALLOW_PRIVATE_AXONS=1` and `TW_REFUSE_IF_COLDKEY_PRESENT=0` are in that
list: they exist for localnet only.

## Flooding and slow clients (spec 8.6, 13.6)

The miner's public port uses httptools with three extra limits:

- **Request-read deadline**: a request must arrive completely (request line,
  headers, body) within `TW_AUTH_MAX_AGE_S + TW_AUTH_ALLOWED_SKEW_S` of its
  first byte. A slower request would be refused as stale anyway. Silent
  connections are closed after the same time. This stops slowloris.
- **Header limits**: 16 KiB for the request line plus headers, 100 fields.
  A head that is still incomplete after that many bytes is refused too. The
  answer is 400, and the connection closes.
- **Ambiguous framing** (`Content-Length` plus `Transfer-Encoding`, two
  different `Content-Length` values, control bytes in header names) is
  refused with 400 (request smuggling).

- **Sender length before decoding** (spec 4.3 step 1, D19): the
  `X-Bittensor-Hotkey` value must be exactly 48 characters (every prefix-42
  address of a 32-byte key has 48) before it is base58-decoded. Base58
  decoding is quadratic in the input length and runs before the signature
  check, so without the bound one unauthenticated request with a 64 KiB
  sender cost about 0.8-1.35 s of CPU (about 50-85 ms at the 16 KiB header
  cap). With the bound it is refused as `tw.auth_malformed` in about 10 µs
  (`reports/phase-3/gate-fix/g4-2-timing.txt`).
- **Streams** (spec 9.2, D29; [streaming.md](streaming.md)): the whole
  request path runs before the first byte; both ends enforce
  `TW_STREAM_MAX_S`, `_MAX_BYTES` and `_IDLE_S`. The miner cuts a stream
  whose reader stopped reading at `max_s` and stops the handler at once when
  the validator disconnects; one caller hotkey may hold at most 16 open
  streams per miner process (429 beyond). The validator cuts a one-byte drip
  by the idle limit (measured between complete events) and an endless stream
  by `max_s` or its time budget. Chunks are JSON objects or arrays, so the
  signed bytes split into chunks one way only. Tests:
  `tests/abuse/test_stream_abuse.py` (drip, endless, 40 unread streams with
  alice served), `tests/integration/test_stream_routes.py` (test 11),
  `tests/unit/test_streaming_client.py`, `tests/property/test_streaming_properties.py`.

The per-IP limiter is the outermost layer, so a flood is refused before any
other work. Its refusals are counted (`tw_rate_limited_total{layer="ip"}`,
`tw_requests_total`), and logged as one `ip_rate_limited` WARNING per client
per 10 s with the number refused, not as one access-log line per request
(logging every refused request would amplify the flood). Measured: 10,000
invalid requests/s from one IP cost the miner 1.45-1.50 cores with 2 workers,
and a permitted validator kept p99 < 71 ms (`docs/benchmarks.md`). One worker
cannot absorb that rate on the reference machine. Run several workers (with
Redis) if you expect it.

## Stricter than the SDK (spec 4.3)

The kit's request verifier refuses, in every language, some requests that
`bittensor.http_auth.verify` accepts:

- step 1, `tw.auth_malformed`: a sender that is not SS58 prefix 42 or not
  exactly 48 characters (checked before base58 decoding, D19); duplicate
  `X-Bittensor-*` headers; a nonce that is not `[0-9]{1,20}`; an
  `X-Bittensor-Crypto` other than exactly `sr25519`/`ed25519`; a signature
  that is not hex digits only (the SDK's `bytes.fromhex` skips whitespace);
- step 4, `tw.auth_bad_signature`, before the replay store is touched: a
  **weak public key** (the sr25519 identity, ed25519 points of small order),
  whose "universal" signature fits any payload (D20, ADR-0010), and a
  signature over the **`<Bytes>`-wrapped** payload (Polkadot-JS `signRaw`;
  A10, D22).

twresp/1 and the v10 wire verify with `crypto.verify(strict=True)`, which
refuses weak keys and `<Bytes>`-wrapped signatures as well. Tests:
`tests/unit/test_verifier.py` (`test_signature_must_be_hex_digits_only`,
`test_weak_key_universal_signature_is_refused_before_the_store`,
`test_bytes_wrapped_signature_is_refused_before_the_store`),
`tests/unit/test_crypto.py`, `tests/unit/test_response_sig.py::test_weak_responder_key_is_refused`,
`tests/property/test_auth_properties.py::test_any_non_hex_character_in_the_signature_is_malformed`.

## Replay stores and clock steps (spec 8.4.3-8.4.4, D21)

Freshness (4.3 step 3) is judged on the miner's wall clock, but replay
stores forget a pair after `retention` on their own clock (the monotonic
clock for the memory store, Redis' clock for `SET NX PX`). If NTP steps the
miner's wall clock **back** by more than `retention − (max_age +
allowed_skew)`, a nonce the store has already forgotten could look fresh
again and be replayed. Three rules close this:

- **2× retention.** Every store must keep pairs for at least
  `2 × (TW_AUTH_MAX_AGE_S + TW_AUTH_ALLOWED_SKEW_S)` (24 s with the
  defaults; the default `TW_NONCE_RETENTION_S=60` gives a 48 s margin). A
  shorter setting refuses to start, for memory and Redis stores alike, and
  for the v10 bridge.
- **Memory store: both clocks.** A pair is forgotten only when `retention`
  has passed on the monotonic clock **and** its nonce is older than
  `retention` on the wall clock.
- **Clock-step guard.** Every authenticated request (before the store is
  consulted) and the 10-minute clock check compare `time.time() −
  time.monotonic()` with the previous value. A drop larger than the margin
  is a backwards step: the miner logs `clock_step_detected` at ERROR, sets
  `tw_clock_step_seconds`, and for `retention` seconds answers every
  authenticated request with **503 `tw.replay_store_unavailable`** and
  `/readyz` with 503 `clock_step`. Then normal service resumes: by then
  every nonce from before the step is outside the freshness window. This
  covers the Redis store too, which cannot see a step on the miner. (The
  alternative of `PXAT nonce + retention` was rejected: it ties expiry to
  Redis' clock and does not cover a step on the miner.)

Unauthenticated requests are refused by the earlier checks as before; the
window does not open the miner to anything, it only refuses work.

## Metagraph staleness (spec 8.5.1)

Callers are checked against the cached metagraph. When the chain cannot be
read:

| Stage | Snapshot age | Behaviour |
|---|---|---|
| Fresh | < `TW_METAGRAPH_SOFT_AGE_S` (900 s) | Normal |
| Degraded | up to `TW_METAGRAPH_MAX_AGE_S` (2 tempos) | Normal policy on the last snapshot; `/readyz` 200 with `degraded: ["metagraph_stale"]` |
| Known callers only | older | Callers that passed policy while the data was fresh or degraded are still served; anyone else gets 503 `tw.metagraph_stale` |

**Trade-off:** a validator that loses its permit, or is deregistered, during
a long chain outage keeps access until the miner can read the chain again.
Unknown or newly permitted callers are never admitted on stale data.
`TW_METAGRAPH_STRICT=1` answers 503 to everyone past the maximum age instead.
Set `TW_CHAIN_FALLBACKS` (or run your own lite node): a shared public
endpoint is the most likely cause of a stale metagraph.

## The legacy v10 bridge (spec 8.11)

The bridge lets old and new nodes talk during a migration. It is opt-in and
always has an end date. What the **v10** scheme protects, and what it does
not:

- It binds the receiver (the axon checks against its own hotkey), the sender
  and the nonce. On TensorWire miners, the kit's own freshness window and
  replay store apply on top; v10 alone allows future nonces and any nonce for
  a new uuid.
- It does **not** cover the HTTP method, the path, or any body field outside
  `required_hash_fields`. Those can be changed on the wire without breaking
  the signature. Put every field that matters in `required_hash_fields`;
  `migrate scan` reports empty or partial lists (TWM100, TWM101) as risks.
- Successful v10 responses are not signed, and v10 Dendrites check no
  response signature at all. Answers from v10 miners therefore carry no
  integrity guarantee; `twresp/1` gives that once a miner has migrated.
- A validator never falls back to v10 for a miner that has answered over
  btauth/1, unless that miner's own signed `ServeAxon` changes its published
  protocol tag away from the kit's (a rollback, D16). A v10-shaped answer on
  its own never causes a downgrade.

Watch `tw_legacy_v10_requests_total` and `tw_legacy_v10_days_remaining`
(alert under 14 days). End the bridge as soon as the rollout allows
(`docs/migration-rollout.md`).

## TLS (spec 16.3, D31, ADR-0011)

Plain HTTP keeps integrity, because requests and responses are both signed,
but not confidentiality. Subnets with private payloads use HTTPS.

**Validators** choose with `TW_SCHEME_POLICY`:

| Mode | Miner published a usable key | Published, but unusable | Nothing published |
|---|---|---|---|
| `http` (default) | plain HTTP (keys ignored) | plain HTTP | plain HTTP |
| `https` | HTTPS, **pinned** | refused, `tw.tls_pin_mismatch` | HTTPS, CA-verified |
| `https-if-tls-published` | HTTPS, **pinned** | refused, `tw.tls_pin_mismatch` | plain HTTP |

- *Pinned*: right after the TLS handshake, and before any request byte is sent,
  the leaf certificate's public key must equal the key the miner published
  with `ServeAxonTls`. CA trust, hostname and dates are not used: the on-chain
  key is the trust anchor (axons are IP addresses). A different key is
  `tw.tls_pin_mismatch` and counts in `tw_tls_pin_failures_total`; it is not
  retried and the miner is **never** reached over plain HTTP instead.
- *Usable*: algorithm byte `0x01` + 32-byte Ed25519 key, or `0x02` + 64-byte
  ECDSA P-256 point (ADR-0011). Anything else a miner published is treated as
  unusable (WARNING once per miner): never a reason to use plain HTTP.
- The v10 fallback is plain HTTP only, so it is used only for miners this mode
  reaches over plain HTTP.
- In `https` mode a miner reachable only over plain HTTP fails with
  `tw.connect_error`.

**Miners** serve TLS in one of two ways. Either way the certificate's key
must be Ed25519 or EC P-256 (RSA keys do not fit on chain; startup refuses
them), and the miner publishes it with `ServeAxonTls`, then reads it back from
the chain: the chain accepts a certificate it does not store (ADR-0011), so a
key that did not land refuses startup.

1. **uvicorn**: `TW_TLS_CERT_FILE` + `TW_TLS_KEY_FILE`. Startup refuses a
   missing or unreadable file, a key file readable by group or others
   (`chmod 600`), an encrypted key (no prompt is ever shown), a key that does
   not match the certificate, and an unsupported key type. Error messages name
   files, never their contents.
2. **A reverse proxy** terminates TLS: `TW_TLS_PUBLISHED_CERT_FILE` is the
   proxy's public certificate (the miner never needs the proxy's private key),
   `TW_TRUSTED_PROXIES` must be set (startup refuses otherwise), and the
   miner binds to loopback. The proxy **must pass the request target and body
   byte for byte**: requests are signed over both, so a proxy that merges
   slashes, decodes percent-encoding, rewrites paths or re-encodes bodies
   makes every request fail with 401 `tw.auth_bad_signature`.
   [`deploy/proxy/Caddyfile`](../deploy/proxy/Caddyfile) and
   [`deploy/proxy/nginx.conf`](../deploy/proxy/nginx.conf) are checked to
   do this (target, body, `X-Forwarded-For`, SSE streaming; evidence in
   `reports/phase-4/wp6/proxy-check.txt`). The kit uses the right-most
   `X-Forwarded-For` address that is not in `TW_TRUSTED_PROXIES` as the
   client address (rate limits); the header is ignored from any other peer.

**Rotating a certificate**: validators pin the key on chain, so a miner that
serves a new certificate before the new key is published is refused
(`tw.tls_pin_mismatch`) until it is. Restart the miner with the new
certificate: it publishes and reads back the key before it opens its port
(if `ServeAxonTls` is rate-limited, startup waits out the subnet's
`serving_rate_limit`). In proxy mode the axon drift check (every 30 minutes)
re-reads `TW_TLS_PUBLISHED_CERT_FILE` and publishes a renewed key; until then
validators refuse the renewed certificate, so renew with the same key (e.g.
certbot `--reuse-key`) or restart the miner right after renewing.
`TW_LEGACY_V10_UNTIL` with TLS is warned about at startup: v10 validators
connect over plain HTTP only. The chain cannot
remove a key: a miner that turns TLS off while a key is published is refused
by validators in the HTTPS modes (startup and `tensorwire doctor` warn).

Test certificates are generated at test time (`tensorwire.testing.tls`);
none is committed. The `tensorwire.tls` functions are listed in
[tls.md](tls.md).

## The migration tools

`tensorwire migrate scan` and `apply` parse the subnet's code with libcst.
They never import or run it. They read and write only `.py` files under the
given directory, never follow or write through symlinks, and never touch
wallets or `.env` files. `apply` refuses to run on a git tree with
uncommitted changes, so `git diff` shows exactly what it changed.

## Other languages and the sidecar (spec 11, 11.6)

The TypeScript, Go and Rust packages apply the same verification rules as the Python kit (every vector in
`conformance/vectors/` in each language; the stricter rules of spec 4.3 everywhere; weak keys refused, ADR-0010),
the same streaming rules (spec 9.2: D35 chunks, D36 slots, the signed trailer) and, through the sidecar client,
the same caller policy and staleness stages. Their miners have no chain access and no wallet beyond their own
hotkey file; the sidecar holds the miner's hotkey for `ServeAxon`. Differences to know about
([multi-language.md](multi-language.md)): stream chunks deeper than 128 levels are refused outside Python (spec
question 9); Rust's axum server has no header read timeout of its own (put a reverse proxy in front, or use
hyper-util's builder); Go and Rust read hotkey files with `secretSeed` only.

## What you still have to do (spec 16.4)

- Run as a non-root user. Wallet directory mode 0700, hotkey file 0600. Keep
  the coldkey off servers entirely (the kit only needs the hotkey).
- Inject secrets (`TW_REDIS_URL` passwords) through a secrets manager or the
  environment, never a committed `.env`.
- Firewall: expose only the miner port. `TW_METRICS_BIND` stays on
  127.0.0.1 (the default) or a private network. Redis is never public.
- Keep time synchronised (chrony); the clock guard only reports drift.
- Enable automatic security updates.
- Run validators and miners on separate hosts. Never run untrusted subnet
  code on a machine that holds a coldkey.
- Behind a reverse proxy, pass the original request target and body
  unchanged (no path normalisation, no re-encoding) and set
  `TW_TRUSTED_PROXIES`; otherwise every request fails verification, or the
  per-IP limit sees only the proxy.

The Docker images and systemd units in `deploy/` apply most of this (non-root
user, read-only hotkey mount, systemd sandboxing); see `deploy/README.md`.
