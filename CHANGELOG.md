# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
