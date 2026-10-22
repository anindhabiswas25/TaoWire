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
