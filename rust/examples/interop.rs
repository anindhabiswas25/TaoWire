//! The Rust side of the live interop check (conformance/interop/live_check.py).
//!
//! ```text
//! cargo run --example interop --features axum,client -- serve 127.0.0.3:8096 <seed-hex> [sr25519|ed25519]
//! cargo run --example interop --features axum,client -- sign <url> <seed-hex> <receiver> [scheme] [count] [body]
//! cargo run --example interop --features axum,client -- stream <url> <seed-hex> <receiver> [scheme] [count]
//! cargo run --example interop --features axum,client,sidecar -- sidecar <url> <token-file> <netuid> <miner> <probes,...>
//! ```
//!
//! `serve` answers `POST /v1/upper` behind the btauth/1 layer with twresp/1
//! signing, and `POST /v1/stream` with five SSE chunks `{"i": n, "text":
//! upper(s)}` and a signed `tw-end` (spec 9.2); `sign` sends `count` requests
//! (fresh signature each) and prints a JSON summary: every answer must be 200
//! with a verified signature. `stream` reads `count` streams the same way
//! (`conformance/interop/stream_check.py`). `sidecar` runs the sidecar client's
//! calls against a real `taowire sidecar` and prints what each returned
//! (`conformance/interop/sidecar_check.py`). Public dev seeds only.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde_json::{json, Value};
use taowire_btauth::axum::{
    error_response, protect, stream_response, BoxError, MinerAuth, StreamConfig, StreamContext,
};
use taowire_btauth::client::Client;
use taowire_btauth::sse::StreamLimits;
use taowire_btauth::{Config, Error, Keypair, MemoryStore, Signer, Verifier};

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

async fn stream_route(Extension(ctx): Extension<StreamContext>, body: Bytes) -> Response {
    let text = match serde_json::from_slice::<Value>(&body) {
        Ok(req) => req["text"].as_str().unwrap_or_default().to_uppercase(),
        Err(e) => return error_response(&Error::new("tw.invalid_request", e.to_string())),
    };
    let chunks = (0..5).map(move |i| -> Result<Vec<u8>, BoxError> {
        Ok(serde_json::to_vec(&json!({"i": i, "text": text}))?)
    });
    let cfg = StreamConfig { route: "/v1/stream".into(), ..StreamConfig::default() };
    stream_response(&ctx, &cfg, futures_util::stream::iter(chunks)).await
}

async fn serve(addr: &str, k: Keypair) {
    let store = Arc::new(MemoryStore::new(Duration::from_secs(60)));
    let verifier = Verifier::new(Config::new(k.ss58(), store)).expect("config");
    println!("serving {addr} as {}", k.ss58());
    let auth = Arc::new(MinerAuth::new(verifier).with_response_key(k));
    let app = Router::new()
        .route("/v1/upper", post(upper))
        .route("/v1/stream", post(stream_route))
        .layer(axum::middleware::from_fn_with_state(auth, protect))
        .route("/healthz", axum::routing::get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}

async fn sign(url: &str, k: Keypair, receiver: &str, count: usize, body: &str) -> bool {
    let (signer, scheme) = (k.ss58().to_owned(), k.scheme().as_str());
    let http = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().expect("http");
    let client = Client::new(Signer::new(k), http);
    let (mut ok, mut statuses, mut errors) = (0, BTreeMap::new(), BTreeMap::new());
    for _ in 0..count {
        match client.send(reqwest::Method::POST, url, body.as_bytes().to_vec(), receiver).await {
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

async fn stream(url: &str, k: Keypair, receiver: &str, count: usize) -> bool {
    let (signer, scheme) = (k.ss58().to_owned(), k.scheme().as_str());
    let client = Client::new(Signer::new(k), reqwest::Client::new());
    let (mut ok, mut errors, mut chunks) = (0, BTreeMap::new(), Vec::<Value>::new());
    for _ in 0..count {
        let body = br#"{"text":"hello"}"#.to_vec();
        let budget = Duration::from_secs(12);
        let res = match client
            .stream(reqwest::Method::POST, url, body, receiver, StreamLimits::default(), budget)
            .await
        {
            Ok(s) => s.finish().await,
            Err(e) => Err(e),
        };
        match res {
            Ok(all) => {
                ok += 1;
                chunks = all.iter().filter_map(|c| serde_json::from_slice(c).ok()).collect();
            }
            Err(e) => *errors.entry(e.code).or_insert(0) += 1,
        }
    }
    let summary = json!({"language": "rust", "signer": signer, "scheme": scheme, "count": count,
                         "ok": ok, "errors": errors, "chunks": chunks});
    println!("{summary}");
    ok == count
}

async fn sidecar_check(url: &str, token_file: &str, netuid: u16, miner: &str, probes: &str) {
    use taowire_btauth::sidecar::{
        Config as SidecarConfig, Decision, ServeAxonError, SidecarClient, POLICY_SCOPE,
    };
    let cfg = SidecarConfig {
        url: url.into(),
        token_file: Some(token_file.into()),
        expected_hotkey: Some(miner.into()),
        ..SidecarConfig::new(netuid)
    };
    let c = std::sync::Arc::new(SidecarClient::new(cfg).expect("sidecar config"));
    let code =
        |r: Result<(), Error>| r.err().map_or_else(|| "ok".to_owned(), |e| e.code.to_owned());
    let start = code(c.start().await);
    let health = match c.health().await {
        Ok(h) => {
            json!({"ok": h.ok, "hotkey": h.hotkey, "stage": format!("{:?}", h.stage), "err": "ok"})
        }
        Err(e) => json!({"err": e.code}),
    };
    let (mut checks, mut callers) = (serde_json::Map::new(), serde_json::Map::new());
    for hk in probes.split(',') {
        checks.insert(hk.into(), json!(code(c.check(hk, POLICY_SCOPE).map(|_| ()))));
        let d = match c.caller(hk).await {
            Ok(Decision::Allowed) => "allowed".to_owned(),
            Ok(Decision::Refused(code)) => code.to_owned(),
            Err(e) => e.code.to_owned(),
        };
        callers.insert(hk.into(), json!(d));
    }
    let (serve, hash_ok) = match c.serve_axon("127.0.0.2", 8099, None).await {
        Ok(h) => ("ok".to_owned(), h.len() == 66),
        Err(ServeAxonError::Chain { code, .. }) => (format!("chain:{code}"), false),
        Err(ServeAxonError::Other(e)) => (e.code.to_owned(), false),
    };
    let wrong = SidecarClient::new(SidecarConfig {
        url: url.into(),
        token: Some("w".repeat(32)),
        ..SidecarConfig::new(netuid)
    })
    .expect("config");
    let wrong = wrong.health().await.err().map_or("ok", |e| e.code);
    let neurons = c.snapshot().map_or(0, |s| s.neurons.len());
    c.stop();
    println!(
        "{}",
        json!({"language": "rust", "start": start, "health": health, "neurons": neurons,
        "stage": format!("{:?}", c.stage()), "check": checks, "caller": callers,
        "serve_axon": serve, "block_hash_ok": hash_ok, "wrong_token": wrong})
    );
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
            let body = arg(7).unwrap_or(r#"{"text":"hello"}"#);
            if !sign(arg(2).expect("url"), k, arg(4).expect("receiver"), count, body).await {
                std::process::exit(1);
            }
        }
        Some("stream") => {
            let k = key(arg(3).expect("seed"), arg(5).unwrap_or("sr25519"));
            let count = arg(6).map_or(1, |c| c.parse().expect("count"));
            if !stream(arg(2).expect("url"), k, arg(4).expect("receiver"), count).await {
                std::process::exit(1);
            }
        }
        Some("sidecar") => {
            let netuid = arg(4).expect("netuid").parse().expect("netuid");
            sidecar_check(
                arg(2).expect("url"),
                arg(3).expect("token file"),
                netuid,
                arg(5).expect("miner"),
                arg(6).unwrap_or(""),
            )
            .await;
        }
        _ => {
            eprintln!("usage: interop serve|sign|stream|sidecar ...");
            std::process::exit(2);
        }
    }
}
