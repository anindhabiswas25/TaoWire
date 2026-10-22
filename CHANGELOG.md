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

### Changed

- `TW_EXTERNAL_IP` is never `0.0.0.0`, `::` or `127.0.0.1`; legacy end dates are at most 180
  days ahead; `TW_METAGRAPH_SOFT_AGE_S` unset means "derive from the tempo".
