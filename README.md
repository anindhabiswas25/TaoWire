# TaoWire

**Secure networking for Bittensor v11 subnets, and the way across from v10.**

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: alpha](https://img.shields.io/badge/status-alpha%200.1.0a2-orange.svg)
![bittensor](https://img.shields.io/badge/bittensor-%3E%3D11.3%2C%3C12-green.svg)
![languages](https://img.shields.io/badge/languages-Python%20%7C%20TypeScript%20%7C%20Go%20%7C%20Rust-lightgrey.svg)

> **Alpha (0.1.0a2).** TaoWire has **not been security-reviewed** yet, and its APIs may change between
> alphas. Use it on localnet and testnet; **do not use it to protect mainnet value**. Feedback and bugs:
> [GitHub issues](https://github.com/anindhabiswas25/TaoWire/issues). Security problems: report them privately through
> [GitHub private vulnerability reporting](https://github.com/anindhabiswas25/TaoWire/security/advisories/new) (see
> [SECURITY.md](SECURITY.md)), never in a public issue.

---

## Why TaoWire

Bittensor v11 removed `Axon`, `Dendrite` and `Synapse`. What it kept is `btauth/1` (hotkey-signed HTTP
requests), `ServeAxon` and the metagraph. Every subnet now has to build its own validator-to-miner
networking, and every team makes its own security mistakes: no replay store, unsigned answers, no caller
checks, no rate limits.

TaoWire is that networking layer, built once, tested hard and secure by default. You write your subnet's
task; TaoWire carries it.

| | Plain v11 SDK | v11 + TaoWire |
|---|---|---|
| Miner HTTP server | write your own | ready, you write only the handler |
| Validator client and scoring loop | write your own | ready: fan-out, retries, SQLite scores, weights with commit-reveal |
| Request signatures (btauth/1) | `sign` / `verify` primitives | verified for you, stricter checks |
| Replay protection across workers | — | Redis nonce store (required with more than 1 worker) |
| Who may call (registered / permit / stake) | — | caller policy built in |
| Signed answers | — | `twresp/1`: each answer is bound to the request's nonce and sender |
| Streaming | — | SSE with a signed `tw-end` trailer |
| Chain outages | — | staged metagraph staleness that fails closed |
| v10 → v11 migration | — | compat layer, `taowire migrate`, two-way bridge for mixed fleets |
| Other languages | Python only | TypeScript, Go and Rust, checked by shared conformance vectors |

## What a subnet looks like

**Miner**: you write the route, TaoWire runs everything around it: body cap, IP rate limit, signature check,
replay store, caller policy, per-hotkey limit, then signs your answer.

```python
from taowire import Miner, RouteContext

miner = Miner.from_env()          # TW_* settings: network, netuid, wallet, ...

@miner.route("/v1/transform", request=TransformRequest, response=TransformResponse, timeout_s=5.0)
async def transform(req: TransformRequest, ctx: RouteContext) -> TransformResponse:
    return TransformResponse(result=req.text.upper())

miner.run()                       # publishes the axon on chain, then serves
```

**Validator**: you write the task and the score, TaoWire queries the miners, verifies every signed answer,
keeps the scores and sets weights.

```python
from taowire import SubnetValidator, Task, ValidatorRunner, ValidatorSettings

class MyValidator(SubnetValidator):
    async def make_task(self, round_id: int) -> Task:
        req = TransformRequest(text="hello", op="upper")
        return Task(route="/v1/transform", body=req.model_dump_json().encode(),
                    response_model=TransformResponse, expected=req)

    async def score(self, task, results):
        want = task.expected.text.upper()
        return {uid: 1.0 if r.ok and isinstance(r.data, TransformResponse) and r.data.result == want else 0.0
                for uid, r in results.items()}

ValidatorRunner(MyValidator(), ValidatorSettings.from_env()).run()
```

A complete working subnet (miner, validator, scoring, tests) is in
[examples/text-ops-subnet](examples/text-ops-subnet), and `taowire init` creates the same project for you.

## Install

| Language | Install | Registry |
|---|---|---|
| Python | `pip install "taowire[all]==0.1.0a2"` | [PyPI](https://pypi.org/project/taowire/0.1.0a2/) |
| TypeScript | `npm install @taowire/btauth@alpha` | [npm](https://www.npmjs.com/package/@taowire/btauth) |
| Go | `go get github.com/anindhabiswas25/TaoWire/go@v0.1.0-alpha.1` | [Go packages](https://pkg.go.dev/github.com/anindhabiswas25/TaoWire/go) |
| Rust | `cargo add taowire-btauth@0.1.0-alpha.1` | [crates.io](https://crates.io/crates/taowire-btauth) |

The alpha is a **pre-release**: a plain `pip install taowire` skips it, so name the version (or use `pip install --pre taowire`).
Optional extras: Python `taowire[redis]`, `taowire[migrate]`, `taowire[ntp]` (`[all]` = all three), `taowire[mcp]` (AI agents); TypeScript peers
`fastify` (server middleware) and `ioredis` (shared replay store); Rust features `axum`, `client`, `redis`, `sidecar`.

## Get started

```bash
uv venv ~/taowire-env && . ~/taowire-env/bin/activate      # or: python -m venv ~/taowire-env
uv pip install "taowire[all]==0.1.0a2"                      # or: pip install "taowire[all]==0.1.0a2"
taowire --version                                           # taowire 0.1.0a2

git clone --depth 1 https://github.com/anindhabiswas25/TaoWire.git ~/taowire-repo   # local-chain scripts
LOCALNET_PYTHON="$(command -v python)" ~/taowire-repo/scripts/localnet_up.sh        # local chain in Docker, a subnet, dev wallets

taowire init ~/my-subnet                                    # a working example subnet
cd ~/my-subnet && uv pip install -e '.[dev]' && pytest -q   # 9 passed
taowire doctor --role miner                                 # checks keys, clock, chain, Redis and settings
```

Follow [docs/quickstart.md](docs/quickstart.md) from there: a miner and a validator on a local chain, up to
weights revealed on chain, in under an hour.

## Use it with your AI agent (MCP)

TaoWire ships an [MCP](https://modelcontextprotocol.io) server, so Claude Code, Claude Desktop, Cursor, VS Code
and other AI coding agents can use the kit directly. Most agents learned Bittensor from v10 and write
`Axon`/`Dendrite`/`Synapse` code that no longer exists; the server keeps them on v11 and TaoWire.

```bash
claude mcp add taowire -- uvx --from "taowire[mcp]==0.1.0a2" taowire mcp
```

Other clients (Claude Desktop, Cursor, VS Code) take the same command in their MCP config; see
[docs/mcp.md](docs/mcp.md). Then ask: *"Use TaoWire to build a subnet where miners caption images"* or
*"Port the v10 subnet in this repo to v11 with TaoWire."*

| Tools | What the agent can do |
|---|---|
| `read_doc`, `search_docs`, `list_settings`, `explain_error` | Read the right docs and settings, explain any `tw.*` error (offline, matches the installed version) |
| `inspect_request`, `inspect_response` | Debug a 401: show the exact signed lines and which check failed |
| `scaffold_project`, `migrate_scan`, `migrate_apply` | Create a subnet; port a v10 subnet (diff first) |
| `doctor`, `read_metagraph` | Check a miner or validator setup; read a subnet (read-only) |

Safe by design: no tool reads private keys or writes to a chain, and tools that write files only write into an
empty directory or a clean git tree.

## Migrating a v10 subnet

```bash
taowire migrate scan  path/to/your-subnet   # what uses Axon / Dendrite / Synapse, and what can be ported
taowire migrate apply path/to/your-subnet   # codemods to the v11 kit (review the diff)
```

`taowire.compat` keeps a v10-shaped API (`Synapse`, `Axon`, `Dendrite`, `Metagraph`) on top of the kit, and a
time-boxed two-way bridge lets v10 and v11 nodes talk while a subnet rolls over. See the
[migration guide](docs/migration-from-v10.md) and the [rollout runbook](docs/migration-rollout.md).

## Other languages

| Language | Package | Notes |
|---|---|---|
| Python | `taowire` | reference implementation: miner, validator, migration, sidecar |
| TypeScript | `@taowire/btauth` | btauth/1, twresp/1, SSE, sidecar client |
| Go | `github.com/anindhabiswas25/TaoWire/go` | btauth/1, twresp/1, SSE, sidecar client |
| Rust | `taowire-btauth` | btauth/1, twresp/1, SSE, sidecar client |

Non-Python miners use a small local sidecar (`taowire sidecar`, loopback only, token-protected) for chain
access: the metagraph, caller policy and `ServeAxon`. All four languages pass the same conformance vectors
and a live cross-language matrix on a local chain. See [docs/multi-language.md](docs/multi-language.md),
[docs/sidecar.md](docs/sidecar.md) and the example miners in [examples/text-ops-miners](examples/text-ops-miners).

## How it was tested

Every release candidate runs the full local gate (`just check`) plus localnet checks on a fresh chain.
On `0.1.0a1` (`0.1.0a2` adds the MCP server: 2,461 Python tests, the gate green again):

- 2,395 Python tests, 277 TypeScript tests, plus the Go and Rust suites; 143/143 conformance vectors in every language; 97% Python coverage.
- Abuse tests: invalid-signature flood, slowloris, 100 MB body, header floods, replay storm, unread streams.
- Fuzzing on every parser of untrusted input (Go native fuzzing, `cargo fuzz`, Hypothesis).
- Localnet: miner and validator end to end, timelocked weights reveal, TLS, streaming, a mixed v10/v11 fleet, a staged
  rollout walk-through, and the four-language interop matrix (200/200 requests per cell, weights revealed).
- Benchmark (`taowire bench`, 4 workers + Redis): about 2,100 verified requests/s, auth + policy p99 under 1 ms, fan-out to
  256 miners in under 0.5 s. See [docs/benchmarks.md](docs/benchmarks.md).

What is **not** done yet: an end-to-end run on the public testnet and an external security review. Both come before 1.0.

## Documentation

- Building: [quickstart](docs/quickstart.md), [AI agents (MCP)](docs/mcp.md), [miner guide](docs/miner-guide.md), [validator guide](docs/validator-guide.md),
  [streaming](docs/streaming.md), [timelock](docs/timelock.md), [TLS](docs/tls.md), [metrics](docs/metrics.md),
  [security](docs/security.md).
- Protocols: [btauth/1 and twresp/1](docs/protocol/), the [legacy v10 bridge](docs/protocol/legacy-v10.md).
- Design decisions: [docs/adr](docs/adr), and the full build specification in
  [TAOWIRE_BUILD_SPEC.md](TAOWIRE_BUILD_SPEC.md).
- Contributing to the kit: [CONTRIBUTING.md](CONTRIBUTING.md).

## Compatibility

| TaoWire | bittensor | Python | Node | Go | Rust |
|---|---|---|---|---|---|
| 0.1.0a2 (alpha) | `>=11.3.0,<12` (tested 11.3.0) | 3.10–3.14 | 20, 22 | 1.22+ | 1.80+ |

## Feedback

This alpha exists to get feedback from subnet builders. Tell us what broke, what was missing and what was hard:
[open an issue](https://github.com/anindhabiswas25/TaoWire/issues). Report security problems privately (see
[SECURITY.md](SECURITY.md)).

## License

[Apache-2.0](LICENSE)
