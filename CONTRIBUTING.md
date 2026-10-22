# Contributing

## Setup

Requirements: [uv](https://docs.astral.sh/uv/), [just](https://just.systems/) (optional: every
recipe is a plain shell command), Python 3.10–3.14.

```bash
just setup              # cd python && uv sync --all-extras
```

## Checks

There is no CI yet. Run the gates by hand before every commit:

```bash
just lint typecheck test    # ruff, ruff format, import-linter, mypy --strict, pytest
just coverage               # coverage report
just migration-test         # compat / migrate / legacy wire tests
```

Without `just`, run the commands from the `justfile` directly.

## Coding rules

- **ADR-0001:** only `chain/gateway.py` performs chain operations. `auth/*` and `crypto.py` may
  import `bittensor.http_auth`, `bittensor.signing` and `bittensor.sp_core`, nothing else from
  `bittensor`. import-linter and `tests/unit/test_architecture.py` enforce this.
- **Secure by default.** A setting that weakens a default must start with `TW_UNSAFE_` or be
  clearly bounded (spec 16.2).
- Error responses use fixed public messages from `tensorwire.errors`; never include stack traces,
  signatures, payloads or internal paths.
- Every public API has a docstring; every Appendix A error path has a test.
- No `TODO`/`FIXME` without a matching entry in the coordination log; no commented-out code.
- No secrets, wallets or `.env` files in git. Tests use only well-known dev keys (`//Alice`, ...).
- Python tests that need a real Redis read `TENSORWIRE_TEST_REDIS_URL` (not a `TW_*` name: unknown
  `TW_*` variables are a startup error).
