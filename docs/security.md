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
| Malicious validator | Leak a miner's answer to another miner before scoring | Timelocked responses (Phase 4) |
| Supply-chain attacker | Poison a release or a dependency | Locked dependencies, `just audit`, signed releases (spec 18) |
| Local attacker on the miner host | Read the hotkey file | Out of scope for code: host hardening below |

## The traps, and how the kit handles each (spec 16.1)

| # | Trap | Default | Proven by |
|---|---|---|---|
| 1 | Replay across processes or hosts | Redis replay store required when `TW_WORKERS > 1` or `TW_INSTANCE_COUNT > 1`; the miner refuses to start with a per-process store; a Redis outage fails closed (503 `tw.replay_store_unavailable`) | `tests/integration/test_miner_process.py`, `test_redis_nonce_store.py`, `tests/unit/test_nonce_store.py`; replay storm across 2 workers never served twice: `tests/abuse/test_abuse.py::test_replay_storm` |
| 2 | Hashing a re-serialised body | Signatures are verified on the raw bytes before parsing; handlers only see verified bytes | integration test 1 (`test_miner_requests.py`), `tests/property/test_auth_properties.py` |
| 3 | Decoded path used as the signed target | The raw request target (`raw_path` + query) is what is verified | `tests/unit/test_miner_app.py`, property tests; conformance P4 (Phase 5) |
| 4 | Clock drift | NTP check at startup and on a schedule; `/readyz` reports `clock_skew`; `tensorwire doctor` checks it | `tests/unit/test_clock_guard.py`, `tests/integration/test_miner_lifecycle.py` |
| 5 | Unbound receiver | Miners always require `X-Bittensor-Receiver` to be their own hotkey; the signer refuses an empty receiver | `tests/unit/test_signer.py`, `tests/unit/test_verifier.py` |
| 6 | Transport retries resend a signed request | The validator client uses `retries=0`; its own retries sign afresh with a new nonce | `tests/unit/test_validator_client.py::test_the_default_transport_never_retries`, `::test_each_attempt_is_signed_afresh_and_bound_to_the_miner` |
| 7 | Authenticated is not authorised | Strict caller policy (registered + permit) by default; staged metagraph staleness (below) | `tests/unit/test_policy.py`, `tests/unit/test_chain_metagraph_cache.py`, `tests/integration/test_miner_requests.py` |
| 8 | Flooding, oversized bodies | Per-IP limit (outermost) → body cap → verification (thread pool, bounded) → per-hotkey limit; request-read deadline, 16 KiB / 100-field header cap | `tests/abuse/test_abuse.py` (all five attacks, `just abuse`), `tests/integration/test_miner_protocol.py`, `tests/unit/test_ratelimit.py`, `tests/unit/test_body_limit.py` |
| 9 | Unsigned responses | `twresp/1` on by default; the validator scores a bad or missing signature as a failure | `tests/unit/test_response_sig.py`, `tests/property/test_response_sig_properties.py`, integration test 10 |
| 10 | Public miner IPs | Documented: firewall, optional proxy, only the miner port exposed; metrics bind to 127.0.0.1 by default | this page ("What you still have to do"), `docs/miner-guide.md` |
| 11 | Answer copying / leaking | Timelock extension (opt-in) | Phase 4 |
| 12 | Weak legacy bridge, both directions | Opt-in; mandatory end dates on both sides (at most 180 days); kit freshness, replay store and caller policy on inbound v10; no downgrade after a miner answered over btauth/1, except when its own signed `ServeAxon` moves its protocol tag away from the kit's (D16); `migrate scan` flags unhashed Synapse fields; traffic counters | `tests/integration/test_legacy_v10_bridge.py` (12, 13), `test_miner_legacy_hook.py`, `test_validator_protocol_tag.py`, `tests/migration/test_migrate_scan.py` (TWM100/TWM101) |
| 19 | Compat hooks weakening security | `blacklist_fn` runs after the caller policy and can only narrow; a custom `verify_fn` is refused at startup | `tests/integration/test_compat_layer.py::test_15_blacklist_cannot_widen_access`, `tests/unit/test_compat.py` |
| 13 | Coldkey on the server | The kit never opens `wallet.coldkey`; a readable unencrypted coldkey stops startup (`TW_REFUSE_IF_COLDKEY_PRESENT=1`) | `tests/integration/test_miner_lifecycle.py`, `tests/integration/test_validator_runner.py`, `tests/unit/test_auth_keys.py` |
| 14 | Supply chain | `uv.lock`, `just audit` (pip-audit), signed releases (spec 18) | `just audit` |
| 15 | Nonce collisions on coarse clocks | Monotonic nanosecond nonce | `tests/unit/test_signer.py` |
| 16 | Redirects breaking target binding / SSRF | `follow_redirects=False`; private and loopback axons rejected unless `TW_ALLOW_PRIVATE_AXONS=1` (localnet) | `tests/unit/test_validator_client.py::test_redirects_are_not_followed`, `tests/unit/test_chain_axon.py` |
| 17 | Error messages leaking internals | Fixed public messages per `tw.*` code; request IDs for correlation; handler exceptions are logged, never sent | `tests/unit/test_errors.py`, `tests/integration/test_miner_requests.py` |
| 18 | Sidecar abuse | Loopback only, bearer token file 0600, fixed netuid | Phase 5 |

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

The per-IP limiter is the outermost layer, so a flood is refused before any
other work. Its refusals are counted (`tw_rate_limited_total{layer="ip"}`,
`tw_requests_total`), and logged as one `ip_rate_limited` WARNING per client
per 10 s with the number refused, not as one access-log line per request
(logging every refused request would amplify the flood). Measured: 10,000
invalid requests/s from one IP cost the miner 1.45-1.50 cores with 2 workers,
and a permitted validator kept p99 < 71 ms (`docs/benchmarks.md`). One worker
cannot absorb that rate on the reference machine. Run several workers (with
Redis) if you expect it.

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

## TLS (spec 16.3)

Plain HTTP keeps integrity, because requests and responses are both signed,
but not confidentiality. Subnets with private payloads must use HTTPS. TLS
termination by the kit, by a reverse proxy, and key pinning against the key a
miner publishes with `ServeAxonTls` arrive in Phase 4.
`TW_SCHEME_POLICY=https-if-tls-published` is refused at startup until then,
so nobody runs without TLS believing they have it.

## The migration tools

`tensorwire migrate scan` and `apply` parse the subnet's code with libcst.
They never import or run it. They read and write only `.py` files under the
given directory, never follow or write through symlinks, and never touch
wallets or `.env` files. `apply` refuses to run on a git tree with
uncommitted changes, so `git diff` shows exactly what it changed.

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
