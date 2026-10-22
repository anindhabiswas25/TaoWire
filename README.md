# TensorWire

**A production-grade networking starter kit for Bittensor v11 subnets, and the migration path for existing v10 subnets.**

> Status: pre-release (Phase 0, foundations). Nothing is published yet. "TensorWire" is a working name.

Bittensor v11 removed `Axon`, `Dendrite` and `Synapse`. What is left is `btauth/1` (hotkey-signed
HTTP), `ServeAxon` and the metagraph. TensorWire fills the gap in between, securely by default:

- **Miner server** (FastAPI): btauth/1 verification in a worker thread, replay protection that
  works across processes (Redis), caller policy (registered, validator permit, stake), body-size
  and rate limits, signed responses (`twresp/1`), health and metrics.
- **Validator client** (httpx): fan-out with fresh signatures per attempt, response verification,
  a scoring loop with SQLite state and weight setting.
- **Migration from v10**: a v10-shaped `tensorwire.compat` layer, a time-boxed two-way bridge for
  mixed fleets, and `tensorwire migrate`.
- **Other languages**: btauth/1 for TypeScript, Go and Rust, checked against shared conformance
  vectors.

## Quickstart

Coming in Phase 2 (`tensorwire init`). For development of the kit itself, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Compatibility

| TensorWire | bittensor allowed | bittensor tested | Python |
|---|---|---|---|
| 0.1.x (dev) | `>=11.3.0,<12` | 11.3.0 | 3.10–3.14 |

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
