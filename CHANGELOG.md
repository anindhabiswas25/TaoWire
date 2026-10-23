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
