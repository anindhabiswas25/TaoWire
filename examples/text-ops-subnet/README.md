# text-ops-subnet

The TaoWire example subnet (spec Section 10). It is deliberately
deterministic, so every answer can be checked exactly; it is used by the
docs, the local tests and the testnet end-to-end run.

- **Task:** the validator sends `{"text": <64-512 random ASCII chars>, "op": "upper" | "reverse" | "sha256"}`
  to `POST /v1/transform`.
- **Miner:** answers `{"result": ...}`.
- **Score:** `1.0` for a correct result, times `max(0.2, 1 - latency_ms / timeout_ms)`;
  a failed request, a bad response signature or a wrong result scores `0`.
- **Weights:** the EMA of the scores, set by TaoWire's weight scheduler.

This directory is exactly what `taowire init text-ops-subnet --package text_ops`
generates, plus this README (`python/tests/integration/test_cli_init.py` keeps
them identical).

## Files

| File | |
|---|---|
| `text_ops/protocol.py` | `TransformRequest`, `TransformResponse`, `expected()`, task generator |
| `text_ops/miner.py` | `register(miner)` adds the route; `python -m text_ops.miner` runs it |
| `text_ops/validator.py` | `TextOpsValidator` (task + scoring); `python -m text_ops.validator` runs it |
| `text_ops/scoring.py` | the score of one answer |
| `tests/test_text_ops.py` | in-process tests on FakeChain (no network) |
| `.env.example` | the `TW_*` settings for localnet |
| `docker-compose.yml` | miner + validator + Redis next to a localnet chain (Linux, host network) |

Miners in TypeScript, Go and Rust implement the same route with byte-identical
results; they arrive with the multi-language packages (Phase 5).

## Tests

```bash
pip install -e '.[dev]'     # from the TaoWire repo: pip install -e ../../python
pytest
```

## Run on localnet

Follow [`docs/quickstart.md`](../../docs/quickstart.md): it starts a local
chain, registers the wallets, runs this miner and validator, and checks that
weights reach the chain.
