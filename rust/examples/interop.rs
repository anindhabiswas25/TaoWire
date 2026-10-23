//! The Rust side of the live interop check (conformance/interop/live_check.py).
//!
//! ```text
//! cargo run --example interop --features axum,client -- serve 127.0.0.3:8096 <seed-hex> [sr25519|ed25519]
//! cargo run --example interop --features axum,client -- sign <url> <seed-hex> <receiver> [scheme] [count]
//! ```
//!
//! `serve` answers `POST /v1/upper` behind the btauth/1 layer with twresp/1
//! signing; `sign` sends `count` requests (fresh signature each) and prints a
//! JSON summary: every answer must be 200 with a verified signature. Public
//! dev seeds only.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tensorwire_btauth::axum::{error_response, protect, MinerAuth};
use tensorwire_btauth::client::Client;
use tensorwire_btauth::{Config, Error, Keypair, MemoryStore, Signer, Verifier};

fn key(seed_hex: &str, scheme: &str) -> Keypair {
    let seed: [u8; 32] = hex::decode(seed_hex.trim_start_matches("0x"))
        .ok()
        .and_then(|v| v.try_into().ok())
        .expect("seed must be 32 bytes of hex");
    if scheme == "ed25519" {
        Keypair::ed25519_from_seed(&seed)
    } else {
        Keypair::sr25519_from_seed(&seed)
    }
}

/// Parses the body itself, like the Python and Go miners: no Content-Type needed.
async fn upper(body: Bytes) -> Response {
    match serde_json::from_slice::<Value>(&body) {
        Ok(req) => Json(json!({"result": req["text"].as_str().unwrap_or_default().to_uppercase()}))
            .into_response(),
        Err(e) => error_response(&Error::new("tw.invalid_request", e.to_string())),
    }
}

async fn serve(addr: &str, k: Keypair) {
    let store = Arc::new(MemoryStore::new(Duration::from_secs(60)));
    let verifier = Verifier::new(Config::new(k.ss58(), store)).expect("config");
    println!("serving {addr} as {}", k.ss58());
    let auth = Arc::new(MinerAuth::new(verifier).with_response_key(k));
    let app = Router::new()
        .route("/v1/upper", post(upper))
        .layer(axum::middleware::from_fn_with_state(auth, protect))
        .route("/healthz", axum::routing::get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}

async fn sign(url: &str, k: Keypair, receiver: &str, count: usize) -> bool {
    let (signer, scheme) = (k.ss58().to_owned(), k.scheme().as_str());
    let http = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().expect("http");
    let client = Client::new(Signer::new(k), http);
    let (mut ok, mut statuses, mut errors) = (0, BTreeMap::new(), BTreeMap::new());
    for _ in 0..count {
        match client
            .send(reqwest::Method::POST, url, br#"{"text":"hello"}"#.to_vec(), receiver)
            .await
        {
            Ok(r) => {
                *statuses.entry(r.status).or_insert(0) += 1;
                ok += usize::from(r.status == 200);
            }
            Err(e) => *errors.entry(e.code).or_insert(0) += 1,
        }
    }
    let summary = json!({"language": "rust", "signer": signer, "scheme": scheme, "count": count,
                         "ok": ok, "statuses": statuses, "errors": errors});
    println!("{summary}");
    ok == count
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |i: usize| args.get(i).map(String::as_str);
    match arg(1) {
        Some("serve") => {
            serve(arg(2).expect("addr"), key(arg(3).expect("seed"), arg(4).unwrap_or("sr25519")))
                .await
        }
        Some("sign") => {
            let k = key(arg(3).expect("seed"), arg(5).unwrap_or("sr25519"));
            let count = arg(6).map_or(200, |c| c.parse().expect("count"));
            if !sign(arg(2).expect("url"), k, arg(4).expect("receiver"), count).await {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: interop serve|sign ...");
            std::process::exit(2);
        }
    }
}
