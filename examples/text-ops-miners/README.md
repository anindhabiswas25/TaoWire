# text-ops miners in TypeScript, Go and Rust

The [text-ops example subnet](../text-ops-subnet/) has its miner in Python. These are the same miner in the other
three languages (spec 10, 11.1): same routes, byte-identical answers, the same TaoWire pipeline. They use their
language's btauth package and the [sidecar](../../docs/sidecar.md) for the parts that need the chain.

| Language | Source | Built on |
|---|---|---|
| Go | [`go/examples/textops-miner/main.go`](../../go/examples/textops-miner/main.go) | `btauth.Middleware` + `go/sidecar` |
| Rust | [`rust/examples/textops_miner.rs`](../../rust/examples/textops_miner.rs) | axum `protect` + the `sidecar` feature |
| TypeScript | [`typescript/examples/textops-miner.ts`](../../typescript/examples/textops-miner.ts) | the Fastify plugin + `@taowire/btauth/sidecar` |

## Routes

| Route | Body | Answer |
|---|---|---|
| `POST /v1/transform` | `{"text": s, "op": "upper" \| "reverse" \| "sha256"}` (text 1–4096 characters) | `{"result": ...}`, signed with twresp/1 |
| `POST /v1/transform/stream` | the same | SSE stream (spec 9.2) of `{"i": n, "piece": ...}` chunks, the result in pieces of 32 characters, then the signed `tw-end` |
| `GET /healthz` | — | `ok` |
| `GET /readyz` | — | 200, or 503 with `metagraph_stale` / `clock_step` |

Each request runs, in order: the per-IP limit (429, unsigned), btauth/1 verification (401), the caller policy
from the sidecar's cached metagraph (403, or 503 `tw.metagraph_stale`, unsigned), the per-hotkey limit (429,
signed), then the handler (422 for a bad body, signed). At startup the miner checks that the sidecar runs with
its hotkey and publishes its axon through it (unless the chain already shows it).

The validator sends ASCII text (`[A-Za-z0-9 ]`), for which every language's `upper` and `reverse` agree with
Python's. For other text the results may differ (e.g. Go's `strings.ToUpper("ß")` is `ß`, Python's is `SS`).

## Run it (localnet)

```bash
just localnet-up                                   # chain + dev wallets in ~/.taowire/localnet
source ~/.taowire/localnet/localnet.env        # TW_NETWORK, TW_NETUID, wallet path
export TW_WALLET_NAME=miner_go TW_ALLOW_PRIVATE_AXONS=1 TW_REFUSE_IF_COLDKEY_PRESENT=0
cd python && uv run taowire sidecar &          # 127.0.0.1:9910, writes $TW_STATE_DIR/sidecar.token
cd ..

export TW_BIND_HOST=127.0.0.3 TW_BIND_PORT=8093 TW_EXTERNAL_IP=127.0.0.3
# Go
cd go && go run ./examples/textops-miner
# Rust
cd rust && cargo run --example textops_miner --features axum,client,sidecar,redis
# TypeScript
cd typescript && npm ci && npm run build:examples && node build/examples/textops-miner.js
```

Run one miner per hotkey, each with its own sidecar (`TW_SIDECAR_PORT`, `TW_SIDECAR_TOKEN_FILE`,
`TW_METRICS_BIND` differ per pair). `conformance/interop/run_matrix.py` (`just interop`) does all of this for the
four miners at once.

## Settings

The miners read the `TW_*` variables of the Python miner that apply to them (spec 12):

| Variable | Default | Notes |
|---|---|---|
| `TW_NETUID`, `TW_WALLET_NAME` | required | |
| `TW_WALLET_PATH`, `TW_WALLET_HOTKEY` | `~/.bittensor/wallets`, `default` | the hotkey file must be owner-only and hold `secretSeed` (Go and Rust; TypeScript also reads `secretPhrase`) |
| `TW_EXTERNAL_IP` | required | published through the sidecar |
| `TW_BIND_HOST`, `TW_BIND_PORT`, `TW_EXTERNAL_PORT` | `0.0.0.0`, `8091`, the bind port | |
| `TW_AUTO_SERVE_AXON` | `1` | publish the axon at startup |
| `TW_SIDECAR_PORT`, `TW_SIDECAR_TOKEN_FILE`, `TW_STATE_DIR` | `9910`, `$TW_STATE_DIR/sidecar.token`, `~/.taowire` | the sidecar on 127.0.0.1 |
| `TW_REQUIRE_PERMIT`, `TW_MIN_CALLER_STAKE_TAO`, `TW_ALLOW_HOTKEYS`, `TW_DENY_HOTKEYS` | `1`, `0`, empty | the caller policy (8.5) |
| `TW_METAGRAPH_STRICT`, `TW_METAGRAPH_SOFT_AGE_S`, `TW_METAGRAPH_MAX_AGE_S` | `0`, 900 s capped at max/2, 2 tempos | the staleness stages (8.5.1) |
| `TW_RATE_IP_PER_S` / `_BURST`, `TW_RATE_HOTKEY_PER_S` / `_BURST` | 50/100, 20/40 | 8.6.2 |
| `TW_AUTH_MAX_AGE_S`, `TW_AUTH_ALLOWED_SKEW_S`, `TW_NONCE_RETENTION_S` | 10, 2, 60 | retention must be ≥ 2 × (max age + skew) |
| `TW_REDIS_URL` | empty | the shared replay store |
| `TW_STREAM_MAX_S`, `TW_STREAM_MAX_BYTES`, `TW_STREAM_IDLE_S`, `TW_STREAM_MAX_PER_CALLER` | 60, 4 MiB, 10, 16 | 9.2, D36 |

Unlike the Python kit, these examples do not refuse unknown `TW_*` variables, and have no TLS, no trusted-proxy
handling (the per-IP limit sees the socket peer) and no Prometheus endpoint. Without a chain,
`conformance/interop/miners_check.py` runs each one against a FakeChain-backed sidecar: routes, byte-identical
answers, caller policy, signed refusals, and slow or silent clients cut within 15 s.
