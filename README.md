# TensorWire

**A production-grade networking starter kit for Bittensor v11 subnets, and the migration path for existing v10 subnets.**

> Status: pre-release (Phase 5: multi-language). Nothing is
> published yet. "TensorWire" is a working name.

Bittensor v11 removed `Axon`, `Dendrite` and `Synapse`. What is left is `btauth/1` (hotkey-signed
HTTP), `ServeAxon` and the metagraph. TensorWire fills the gap in between, securely by default:

- **Miner server** (FastAPI): btauth/1 verification in a worker thread, replay protection that
  works across processes (Redis), caller policy (registered, validator permit, stake), body-size
  and rate limits, signed responses (`twresp/1`), health and metrics.
- **Validator client** (httpx): fan-out with fresh signatures per attempt, response verification,
  a scoring loop with SQLite state and weight setting.
- **Migration from v10**: a v10-shaped `tensorwire.compat` layer, a time-boxed two-way bridge for
  mixed fleets, and `tensorwire migrate`.
- **Other languages**: btauth/1, twresp/1 and signed SSE streams for TypeScript, Go and Rust, checked
  against shared conformance vectors, with caller policy and `ServeAxon` through a loopback sidecar
  ([multi-language](docs/multi-language.md), [sidecar](docs/sidecar.md), example miners in
  [examples/text-ops-miners](examples/text-ops-miners/README.md)).

## Quickstart

[docs/quickstart.md](docs/quickstart.md): a subnet with a miner and a validator on a local chain,
from `tensorwire init` to weights on chain. For development of the kit itself, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- Building: [miner guide](docs/miner-guide.md), [validator guide](docs/validator-guide.md),
  [metrics](docs/metrics.md), [security](docs/security.md), [benchmarks](docs/benchmarks.md).
- Migrating a v10 subnet: [migration guide](docs/migration-from-v10.md) (`tensorwire migrate
  scan` / `apply`), [rollout runbook](docs/migration-rollout.md) (`tensorwire migrate status`),
  [case studies](docs/migrations/).
- Protocols: [btauth/1 and twresp/1](docs/protocol/), the [legacy v10 bridge](docs/protocol/legacy-v10.md).
- Other languages: [multi-language](docs/multi-language.md) (TypeScript, Go, Rust), [the sidecar](docs/sidecar.md),
  package READMEs in [go/](go/README.md), [rust/](rust/README.md), [typescript/](typescript/README.md).

## Compatibility

| TensorWire | bittensor allowed | bittensor tested | Python |
|---|---|---|---|
| 0.1.x (dev) | `>=11.3.0,<12` | 11.3.0 | 3.10–3.14 |

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
