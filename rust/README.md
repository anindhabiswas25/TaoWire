# tensorwire-btauth (Rust)

btauth/1 signed requests and twresp/1 signed responses for Bittensor v11 subnets: the Rust crate of
[TensorWire](../README.md) (spec 11.5). Rust ≥ 1.80, `#![forbid(unsafe_code)]`. Not published.

Features: `axum` (middleware), `client` (reqwest), `redis` (shared replay store). Default: none.

## Quickstart (miner, feature `axum`)

```rust
use std::{sync::Arc, time::Duration};
use axum::{body::Bytes, routing::post, Extension, Router};
use tensorwire_btauth::{axum::{protect, MinerAuth}, Caller, Config, Keypair, MemoryStore, Verifier};

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

A runnable miner and signer with dev keys: `examples/interop.rs`
(`cargo run --example interop --features axum,client -- serve 127.0.0.3:8096 <seed-hex>`).

Validator side (feature `client`): `Client::new(Signer::new(validator_key), reqwest_client)` and
`client.send(Method::POST, url, body, miner_hotkey).await`; `Ok` means the twresp/1 signature verified.

## API

| Item | What it does |
|---|---|
| `build_payload`, `body_sha256`, `Scheme` | The 8-line btauth/1 payload (spec 4.2) |
| `Verifier::new(Config)`, `Verifier::verify(headers, body, method, target).await` | Spec 4.3 in order; `Caller` or `Error { code, status, .. }` (Appendix A) |
| `axum::protect`, `axum::MinerAuth` | Middleware: `OriginalUri` path and query as target (percent-encoding kept, absolute form refused), `to_bytes` with the body limit (413), `Caller` and raw `Bytes` in extensions, twresp/1 on answers with a response key |
| `Keypair::{sr25519_from_seed, ed25519_from_seed}`, `Keypair::sign` | schnorrkel (context `b"substrate"`) and ed25519-dalek 2 |
| `Signer::sign` | Request headers with a fresh nonce every call |
| `NonceSource` | `AtomicU64` + `fetch_update`: `max(now_ns, last + 1)` |
| `MemoryStore`, `NonceStore`; `redis_store::RedisStore` | Replay stores; Redis keys match the Python kit (`tw:n:<hotkey>:<nonce>`) |
| `sign_response`, `verify_response`, `verify_response_digest` | twresp/1 (spec 9.1; digest form for 9.2 streams) |
| `client::Client::send` | Signed request + verified answer; client codes `tw.timeout`, `tw.connect_error`, `tw.response_too_large`, `tw.bad_response_signature` |
| `decode_ss58`, `encode_ss58`, `is_weak_public_key` | Appendix D (prefix 42 only), weak-key rule |
| `Error`, `codes`, `status_of`, `error_body` | Appendix A codes, statuses and the JSON error body |

ed25519 uses `verify` (RFC 8032), not `verify_strict`, plus the weak-key refusal: see
[ADR-0010](../docs/adr/0010-ed25519-verify-and-weak-keys.md). API docs: `cargo doc --all-features --open`.

## Checks

```bash
cd rust
cargo test --test conformance          # every vector in conformance/vectors (except legacy_v10)
cargo test --all-features              # + integration tests; TENSORWIRE_TEST_REDIS_URL for Redis
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings
cargo +nightly fuzz run verify -- -max_total_time=300
cargo audit
```

Not yet in this crate: SSE streaming helpers (spec 9.2) and the sidecar client (11.6).
