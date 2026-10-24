# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Renamed

- The project is now **TaoWire** (spec v1.10, D46): the Python distribution and import package
  `taowire` (CLI `taowire`, state directory `~/.taowire`), the npm package `@taowire/btauth`, the
  Rust crate `taowire-btauth` and the Go module `github.com/anindhabiswas25/TaoWire/go`. Nothing
  was published under the old name, so there is no alias. Wire and operator names are unchanged:
  `TW_*` settings, `tw.*` error codes, `twresp/1`, `X-TW-Resp-*`, `tw-end`, `tw_*` metrics, `TWM*`
  rule ids and the btauth/1 headers. Entries below that were written before the rename use the old
  name, TensorWire (`tensorwire`).

### Added

- Repository skeleton, `justfile` quality gates, ruff / mypy `--strict` / import-linter rules
  (ADR-0001: chain access only through `chain/gateway.py`).
- `tensorwire.errors`: error hierarchy and every Appendix A error code.
- `tensorwire.config`: miner, validator and sidecar settings for every `TW_*` variable, with range
  checks and an error for unknown `TW_*` variables.
- `tensorwire.auth.signer`: `MonotonicNonce` and receiver-bound `RequestSigner`.
- `tensorwire.auth.nonce_store`: `MemoryNonceStore` and `RedisNonceStore` (fail-closed).
- `tensorwire.limits.body`: ASGI body-size cap; `tensorwire.limits.ratelimit`: memory token
  buckets and trusted-proxy client IP resolution.
- `tensorwire.auth.verifier`: thread-offloaded btauth/1 verification with `tw.auth_*` error
  mapping; rejects sender addresses that are not SS58 prefix 42, duplicate `X-Bittensor-*`
  headers, non-decimal nonces and inexact `X-Bittensor-Crypto` values as `tw.auth_malformed`.
- `tensorwire.auth.clock`: NTP clock guard (`/readyz` reports `clock_skew`).
- `tensorwire.auth.keys`: hotkey-only loading and the coldkey guard; `tensorwire.auth.sdk_check`.
- `tensorwire.policy`: `CallerPolicy` (deny > allow > registered > permit > stake) and
  `CallerGate` with the staged metagraph staleness rule (known callers only past the max age).
- `tensorwire.Miner`: protected routes, the request pipeline of spec 5.3, startup lifecycle
  (SDK check, coldkey refusal, registration check, axon publishing), `/healthz`, `/readyz`,
  Prometheus metrics on a separate bind, JSON logs and request IDs.
- `tensorwire.testing`: dev keys, `FakeClock`, `FakeMetagraphSource`, `SignedClient`, and the
  `fake_chain` / `tw_miner` / `miner_app` / `signed_client` pytest fixtures.
- `tensorwire sign-request`: print a curl command with btauth/1 headers, or send it.
- `twresp/1` signed responses (`tensorwire.extensions.response_sig`, ADR-0004): miners sign
  200s and post-authentication errors; validators verify them.
- `tensorwire.validator`: `ValidatorClient` (per-attempt signatures, raw-path binding, no
  transport retries, response cap, `MinerResult` with `protocol` and `response_verified`),
  miner selection, `SubnetValidator` / `Task` / `ValidatorRunner`, SQLite score store with EMA
  and hotkey-change reset (ADR-0005), weight scheduler (`ok` = commit included), one signing
  process per hotkey (lock file), health and metrics.
- Legacy v10 bridge hooks: miner routes with `legacy_synapse` / `legacy_body_hash` answer v10
  validators while `TW_LEGACY_V10_UNTIL` is set; `ValidatorClient(legacy=, selector=)` reaches
  v10 miners (the wire format is `extensions/legacy_v10`).
- `tensorwire.compat` (ADR-0007): `Synapse`, `TerminalInfo`, `Axon`, `Dendrite`, `AxonInfo`,
  `axons_from`, `Metagraph`, `weights.to_mapping`.
- `tensorwire migrate scan`: v10 → v11 report (text / JSON / Markdown) with security checks.
- `tensorwire init`: scaffold a subnet project whose tests pass out of the box.
- `tensorwire doctor`: check a miner's or validator's host setup.
- `examples/text-ops-subnet` and the archived v10 template ported to `compat`
  (`examples/migrations/template-v10-to-v11`).
- Docs: quickstart, validator guide, migration from v10, template case study.

### Changed

- The miner retries `ServeAxon` after the subnet's `serving_rate_limit` blocks, read from the
  chain (was a fixed 50).
- Ctrl-C stops a miner or validator cleanly with exit status 130 (no traceback).

- `TW_EXTERNAL_IP` is never `0.0.0.0`, `::` or `127.0.0.1`; legacy end dates are at most 180
  days ahead; `TW_METAGRAPH_SOFT_AGE_S` unset means "derive from the tempo".

### Security

- The sender address must be exactly 48 characters before it is base58-decoded (decoding is
  quadratic and ran before authentication; a 64 KiB sender cost about a second of CPU).
- Weak public keys (the sr25519 identity, ed25519 points of small order) and signatures over
  the `<Bytes>`-wrapped payload are refused as `tw.auth_bad_signature` by the request
  verifier, and by `crypto.verify(strict=True)` (twresp/1, the v10 wire); signature headers
  must be hex digits only (ADR-0010).
- Replay stores must keep pairs for at least `2 × (max_age + allowed_skew)`; the memory store
  forgets a pair only when both clocks agree; a backwards wall-clock step larger than the
  margin fails closed for `retention` seconds (503 `tw.replay_store_unavailable`, `/readyz`
  `clock_step`, `clock_step_detected`, `tw_clock_step_seconds`).
- Native `legacy_body_hash` v10 answers holding `inf` / `nan` are refused (500) instead of
  being sent as `null`.

### Added (Phase 3 gate fixes)

- `compat.TemplateMinerAdapter`, and the template surface on both adapters: hotkey-only
  `wallet`, read-only `subtensor`, `sync()`, `check_registered()`, pinned `metagraph`; the
  validator adapter starts the kit on its first chain read. `compat.config`,
  `compat.add_v10_args`, `compat.Config`. `Miner.serve_in_background()`.
- `migrate apply`: customised template bases are put on the adapters (TWM026, now auto);
  new auto rules TWM031 (v10 config calls), TWM032 (`bt.logging` set-up statements), TWM033
  (`bt.Wallet(config=...)`).
- `tensorwire bench` reaches Redis directly by default (container IP / host network) and
  prints which path it used; a `docker-proxy` run is marked as extra information.
- Case studies: llm-detection (S6 recounted with its bases), data-universe.

### Added (Phase 4: extensions)

- Streaming (spec 9.2, D29): `@miner.route(..., stream=True)` streams `event: chunk` frames
  after the whole request pipeline and ends with a signed `tw-end` trailer (digest, count,
  twresp/1); `ValidatorClient.stream()` / `query_stream()` / `query_stream_many()` hand out
  unverified chunks, then a verified `MinerResult`. `TW_STREAM_MAX_S`, `TW_STREAM_MAX_BYTES`,
  `TW_STREAM_IDLE_S` (per route and per call too); `tw_stream_aborted_total`. Integration
  test 11. `docs/streaming.md`.
- `compat.StreamingSynapse` (10b.2.1, D33) on `compat.Axon` and
  `compat.Dendrite(streaming=True)`; TWM002 is auto; new risk rule TWM034 (streaming routes
  in a mixed fleet; v10-wire streaming is not supported).
- Timelock (spec 8.10, D30): sealed challenges and sealed responses (`Task(sealed=True)`,
  `Miner.timelock`), `bt.timelock` only through the chain gateway, a process-wide drand
  limiter, retries and deadlines (`TW_TIMELOCK_CONCURRENCY`, `_RETRIES`, `_TIMEOUT_S`);
  `tw.timelock_unavailable`, `tw_timelock_open_total{result}`; opt-in `drand` test marker.
  `docs/timelock.md`.
- TLS (spec 16.3, D31, ADR-0011): HTTPS from uvicorn (`TW_TLS_CERT_FILE` / `TW_TLS_KEY_FILE`)
  or at a reverse proxy (`TW_TLS_PUBLISHED_CERT_FILE`), the key published with `ServeAxonTls`;
  validators `TW_SCHEME_POLICY=https` / `https-if-tls-published` pin the published key and never
  fall back to HTTP for a miner that published one (`tw.tls_pin_mismatch`,
  `tw_tls_pin_failures_total`). `deploy/proxy` Caddy and nginx examples; `docs/tls.md`.
- `compat.Subtensor` (10b.2.6, D34): v10 `subtensor` reads and commitments on the kit's
  gateway (`ChainGateway.block_hash`, `commitment`, `storage`, `commit`), hotkey-signed only;
  other v10 writes raise `NotImplementedError` naming the v11 replacement. `migrate`: TWM008
  is auto, new TWM035 (`bt.AsyncSubtensor`) and TWM036 (writes the facade does not perform).

### Changed (Phase 4)

- Timelocked weight commits rejected for their reveal round (`expired` / `too_early`) are
  re-planned as new extrinsics, at most 3 per weight window (spec 8.9, D32).
- `just check` never falls back to a host Go tool: `scripts/go_tools.sh` builds the pinned
  staticcheck / govulncheck or fails clearly (D23).
- The G3-3 startup refusal of `https-if-tls-published` is lifted (ADR-0011 accepted).
- TWM100 / TWM101 fix text warns that changing `required_hash_fields` breaks a mixed fleet
  (D28; also `docs/migration-rollout.md`).
- Case study recounts: data-universe S6 91 → 24 (`compat.Subtensor`), llm-detection 8,
  template 17.

### Security (Phase 4)

- At most 16 open streams per caller hotkey per miner process (429 beyond); a stream that
  stalls, drips or never ends is cut on both sides.
- Sealed answers are bound to the miner that sealed them; stale sealed challenges are refused
  without a drand fetch.
- Chain data for TLS keys is decoded strictly and fails closed; the pin is checked inside the
  TLS handshake (no renegotiation).

### Added (Phase 5: multi-language)

- TypeScript package `@tensorwire/btauth` (spec 11.3): btauth/1 sign and verify (WASM sr25519 / ed25519),
  memory and Redis replay stores, the Fastify adapter, the fetch client, twresp/1; every conformance vector.
- SSE streaming with a signed `tw-end` trailer in TypeScript, Go and Rust (spec 9.2, D29, D35, D36): miner side
  (`streamReply`, `ServeStream`, `axum::stream_response`) with per-caller stream slots and the three limits,
  client side (`Client.stream`) with the strict trailer, unverified chunks until it verifies, no read timeout
  beyond the limits; linear SSE parsers with property and fuzz tests; `stream_check.py` cross-language checks
  with a tampering relay.
- `tensorwire sidecar` (spec 11.6): loopback-only service for non-Python miners — `/v1/health`,
  `/v1/metagraph`, `/v1/caller/{hotkey}`, `/v1/serve-axon`; bearer token from an owner-only file; every chain
  call through the gateway. Clients in TypeScript (`@tensorwire/btauth/sidecar`), Go (`go/sidecar`) and Rust
  (feature `sidecar`) with the metagraph cache, the 8.5.1 staleness stages and the Python caller policy.
- Example text-ops miners in TypeScript, Go and Rust (spec 10), byte-identical to the Python miner, with a
  streaming route; the Python example and `tensorwire init` gain `POST /v1/transform/stream`.
- `conformance/interop/run_matrix.py` and `just interop` (spec 13.5): the localnet matrix of the four miners,
  the Python validator and the TS / Go / Rust client signers, with weights revealed in the same run.
- Go and Rust: token buckets, hotkey-file loaders; Go `MiddlewareConfig.Policy`, Rust `MinerAuth::with_policy`
  and `with_body_timeout`.
- `TW_STREAM_MAX_PER_CALLER` (default 16, 1–256; D36, G6-3).
- `WeightsVersionKey` preflight before a commit (D38, G6-4): `ChainGateway.weights_version_key`; a stale
  `TW_WEIGHTS_VERSION_KEY` commits nothing, logs `weights_version_key_stale` and counts
  `tw_validator_weight_submissions_total{ok="false",code="version_key_stale"}`.
- New error code `tw.sidecar_unauthorized` (401; spec question 10).

### Changed (Phase 5)

- The sdist is built from an explicit include list (G6-1): a git-ignored virtualenv such as `.venv-py310` no
  longer breaks `uv build`.
- The unread-streams abuse test uses the 13.6 pass rule of D42 (the attacker's 503
  `tw.replay_store_unavailable` is a valid refusal) (G6-5).
- Caller-policy settings are shared by the miner and the sidecar (`CallerPolicySettings`).
- The TypeScript Fastify adapter answers `tw.metagraph_stale`, `tw.replay_store_unavailable` and `tw.internal`
  unsigned after authentication, as the Python pipeline does (it signed them before).
- `just lint` builds the TypeScript (TypeDoc, every export documented) and Rust (rustdoc, warnings as errors) API
  docs; a Go test checks every exported identifier has a doc comment.

### Security (Phase 5)

- Stream clients and miners in every language refuse chunks that are not JSON objects or arrays, and chunks
  nested deeper than 128 (spec question 9); counts written `-0` or above u64 are refused in the trailer.
- Go and Rust stream clients never follow redirects; the Go stream server recovers a panicking chunk source.
- Rust `StreamConfig::default()` shares one process-wide `StreamSlots` (a per-request default reset D36).
- The Go and Rust sidecar policy hooks use one known-callers scope (a caller inventing paths could fill the
  bounded set and evict other validators during an outage).
- Sidecar clients judge a snapshot newer by its block (a slow answer of the same stale snapshot no longer clears
  the known callers).

### Changed (Phase 5 gate carry-overs)

- Python streaming applies D43 like Go, Rust and TypeScript (G7-1, spec 9.2): `encode_chunk` / `decode_chunk`
  refuse chunks nested deeper than 128 (`MAX_CHUNK_DEPTH`), and `parse_trailer` refuses a `count` that is not a
  plain non-negative integer literal fitting a u64 (`-0`, fractions, exponents) and lone UTF-16 surrogate escapes.
  Go and TypeScript now refuse lone surrogate escapes in the trailer too (Rust's `serde_json` already did).
  `encode_chunk` on a value deeper than the interpreter's recursion limit raises `ChunkError` (it raised
  `RecursionError`).
- The Rust example miner serves through hyper's `http1::Builder` with a header read timeout of
  `TW_AUTH_MAX_AGE_S + TW_AUTH_ALLOWED_SKEW_S` (G7-2; `axum::serve` has none): a client sending its headers
  slowly, or nothing at all, is cut after 12 s by default. The TypeScript example miner lowers Node's
  `connectionsCheckingInterval` to 1 s, so its 10 s header and request timeouts fire on time (they waited for
  Node's 30 s check before). `conformance/interop/miners_check.py` checks both cases for every example miner.
