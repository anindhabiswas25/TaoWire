# taowire-btauth (Rust)

> **Alpha (0.1.0a1).** TaoWire has **not been security-reviewed** yet, and its APIs may change between
> alphas. Use it on localnet and testnet; **do not use it to protect mainnet value**. Feedback and bugs:
> [GitHub issues](https://github.com/anindhabiswas25/TaoWire/issues). Security problems: report them privately through
> [GitHub private vulnerability reporting](https://github.com/anindhabiswas25/TaoWire/security/advisories/new) (see
> [SECURITY.md](https://github.com/anindhabiswas25/TaoWire/blob/main/SECURITY.md)), never in a public issue.

btauth/1 signed requests and twresp/1 signed responses for Bittensor v11 subnets: the Rust crate of
[TaoWire](https://github.com/anindhabiswas25/TaoWire) (spec 11.5). Rust ≥ 1.80, `#![forbid(unsafe_code)]`.

```toml
[dependencies]
taowire-btauth = { version = "0.1.0-alpha.1", features = ["axum"] }
```

Features: `axum` (middleware), `client` (reqwest), `redis` (shared replay store), `sidecar` (sidecar client,
implies `client`). Default: none.

## Quickstart (miner, feature `axum`)

```rust
use std::{sync::Arc, time::Duration};
use axum::{body::Bytes, routing::post, Extension, Router};
use taowire_btauth::{axum::{protect, MinerAuth}, Caller, Config, Keypair, MemoryStore, Verifier};

#[tokio::main]
async fn main() {
    let key = Keypair::sr25519_from_seed(&miner_seed()); // 32-byte secretSeed of the miner hotkey
    let store = Arc::new(MemoryStore::new(Duration::from_secs(60)));
    let verifier = Verifier::new(Config::new(key.ss58(), store)).unwrap();
    let auth = Arc::new(MinerAuth::new(verifier).with_response_key(key));
    let app = Router::new()
        .route("/v1/echo", post(|Extension(c): Extension<Caller>, body: Bytes| async move {
            format!("{}: {}", c.hotkey, String::from_utf8_lossy(&body))
        }))
        .layer(axum::middleware::from_fn_with_state(auth, protect));
    let listener = tokio::net::TcpListener::bind("127.0.0.2:8091").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

A full miner (caller policy and `ServeAxon` through the [sidecar](https://github.com/anindhabiswas25/TaoWire/blob/main/docs/sidecar.md), per-IP and per-hotkey
limits, a streaming route): [`examples/textops_miner.rs`](https://github.com/anindhabiswas25/TaoWire/blob/main/rust/examples/textops_miner.rs)
(`cargo run --example textops_miner --features axum,client,sidecar,redis`; settings in
[examples/text-ops-miners](https://github.com/anindhabiswas25/TaoWire/blob/main/examples/text-ops-miners/README.md)).

A runnable miner and signer with dev keys: `examples/interop.rs`
(`cargo run --example interop --features axum,client,sidecar -- serve 127.0.0.3:8096 <seed-hex>`).

Validator side (feature `client`): `Client::new(Signer::new(validator_key), reqwest_client)` and
`client.send(Method::POST, url, body, miner_hotkey).await`; `Ok` means the twresp/1 signature verified.

## API

| Item | What it does |
|---|---|
| `build_payload`, `body_sha256`, `Scheme` | The 8-line btauth/1 payload (spec 4.2) |
| `Verifier::new(Config)`, `Verifier::verify(headers, body, method, target).await` | Spec 4.3 in order; `Caller` or `Error { code, status, .. }` (Appendix A). Refuses a store with retention below `2 × (max_age + allowed_skew)` (D21) |
| `Verifier::failing_closed`, `Verifier::last_clock_step` | Clock-step guard (D21): after a backwards wall-clock step larger than the store's margin, requests get `tw.replay_store_unavailable` for the retention; report it as not-ready (`clock_step`). Tests set `Config::now_ns` and `Config::monotonic_ns` |
| `axum::protect`, `axum::MinerAuth` | Middleware: `OriginalUri` path and query as target (percent-encoding kept, absolute form refused), `to_bytes` with the body limit (413), `Caller` and raw `Bytes` in extensions, twresp/1 on answers with a response key |
| `Keypair::{sr25519_from_seed, ed25519_from_seed}`, `Keypair::sign` | schnorrkel (context `b"substrate"`) and ed25519-dalek 2 |
| `Signer::sign` | Request headers with a fresh nonce every call |
| `NonceSource` | `AtomicU64` + `fetch_update`: `max(now_ns, last + 1)` |
| `MemoryStore`, `NonceStore`; `redis_store::RedisStore` | Replay stores; Redis keys match the Python kit (`tw:n:<hotkey>:<nonce>`) |
| `sign_response`, `verify_response`, `verify_response_digest` | twresp/1 (spec 9.1; digest form for 9.2 streams) |
| `client::Client::send` | Signed request + verified answer; client codes `tw.timeout`, `tw.connect_error`, `tw.response_too_large`, `tw.bad_response_signature` |
| `axum::stream_response`, `axum::StreamConfig`, `axum::StreamContext` | SSE stream with a signed `tw-end` from a protected handler (spec 9.2): per-caller slots (D36), first chunk before any byte, limits, abort hook |
| `client::Client::stream`, `client::Stream`, `client::UnverifiedChunk` | Streaming query: `next().await` gives unverified chunks, `Ok(None)` only after the trailer verified |
| `TokenBuckets`, `RateLimit`, `DEFAULT_IP_LIMIT`, `DEFAULT_HOTKEY_LIMIT` | Per-IP / per-hotkey token buckets (spec 8.6.2) |
| `Keypair::from_hotkey_file(path, scheme)` | A Bittensor hotkey file (owner-only, `secretSeed`, `ss58Address` checked) |
| `axum::MinerAuth::with_body_timeout`, `MinerAuth::verifier` | Body read deadline (default 10 s); the verifier for readiness probes. `axum::serve` has no header read timeout: serve with hyper's `http1::Builder::header_read_timeout`, as `examples/textops_miner.rs` does |
| `axum::MinerAuth::with_policy`, `PolicyFn` | Caller policy after verification (spec 8.5); refusals signed except `axum::UNSIGNED_CODES` |
| `sidecar::{SidecarClient, Config, CallerPolicy, read_token_file, parse_snapshot, parse_decision, parse_health}` | Feature `sidecar`: the sidecar client (spec 11.6, `docs/multi-language.md` "Sidecar API") — cached metagraph with the 8.5.1 stages, the Python caller policy, `serve_axon` |
| `sse::{Parser, decode_chunk, encode_chunk, parse_trailer, encode_trailer, encode_event, StreamDigest, StreamLimits, StreamSlots}` | The shared stream pieces (WHATWG SSE parser, D35 chunk rule, strict trailer) |
| `decode_ss58`, `encode_ss58`, `is_weak_public_key` | Appendix D (prefix 42 only), weak-key rule |
| `Error`, `codes`, `status_of`, `error_body` | Appendix A codes, statuses and the JSON error body |

ed25519 uses `verify` (RFC 8032), not `verify_strict`, plus the weak-key refusal: see
[ADR-0010](https://github.com/anindhabiswas25/TaoWire/blob/main/docs/adr/0010-ed25519-verify-and-weak-keys.md). API docs: `cargo doc --all-features --open`.

## Checks

```bash
cd rust
cargo test --test conformance          # every vector in conformance/vectors (except legacy_v10)
cargo test --all-features              # + integration tests; TAOWIRE_TEST_REDIS_URL for Redis
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings
cargo +nightly fuzz run verify -- -max_total_time=300   # also: sse, trailer, sidecar
cargo audit
```

