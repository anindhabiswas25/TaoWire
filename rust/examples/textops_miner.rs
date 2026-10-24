//! The text-ops example subnet's miner in Rust (spec 10, 11.1): the same routes
//! and byte-identical answers as the Python miner in `examples/text-ops-subnet`,
//! on the axum `protect` layer, with caller policy and serve-axon from the
//! TaoWire sidecar (`taowire sidecar`, spec 11.6).
//!
//! ```text
//! POST /v1/transform         {"text": s, "op": "upper"|"reverse"|"sha256"} -> {"result": ...}
//! POST /v1/transform/stream  the same, as an SSE stream of {"i": n, "piece": ...} (32 characters each)
//! GET  /healthz, /readyz
//! ```
//!
//! Each connection must deliver a request's line and headers within
//! `TW_AUTH_MAX_AGE_S + TW_AUTH_ALLOWED_SKEW_S` (the Python miner's
//! request-read deadline; a slower request would be stale anyway), and a body
//! within the body timeout, so slow clients cannot hold connections open.
//!
//! Every request runs, in order: the per-IP limit (429, unsigned), btauth/1
//! verification, the caller policy from the sidecar's metagraph (403 / 503),
//! the per-hotkey limit (429, signed), then the handler; answers after
//! authentication are signed with twresp/1. Configuration is the `TW_*`
//! variables of the Python miner that apply (`examples/text-ops-miners/README.md`).
//!
//! ```text
//! cargo run --example textops_miner --features axum,client,sidecar,redis
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use taowire_btauth::axum::{
    error_response, protect, stream_response, BoxError, MinerAuth, StreamConfig, StreamContext,
};
use taowire_btauth::redis_store::RedisStore;
use taowire_btauth::sidecar::{
    CallerPolicy, Config as SidecarConfig, ServeAxonError, SidecarClient, Stage,
};
use taowire_btauth::sse::{StreamLimits, StreamSlots};
use taowire_btauth::{
    codes, Caller, Config, Error, Keypair, MemoryStore, NonceStore, RateLimit, Scheme,
    TokenBuckets, Verifier,
};
use tokio::net::TcpListener;
use tower::ServiceExt as _;

const ROUTE: &str = "/v1/transform";
const STREAM_ROUTE: &str = "/v1/transform/stream";
const PIECE_CHARS: usize = 32;
const MAX_BODY: usize = 64_000;
const MAX_TEXT: usize = 4096;
/// The Python route's `timeout_s`.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The one correct answer (Python's `str.upper`, `[::-1]`, sha256 of UTF-8).
/// For ASCII, which the validator sends, every language agrees.
fn expected(text: &str, op: &str) -> String {
    match op {
        "upper" => text.to_uppercase(),
        "reverse" => text.chars().rev().collect(),
        _ => hex::encode(Sha256::digest(text.as_bytes())),
    }
}

/// The body like the Python model: an object with `text` (1-4096
/// characters) and `op` (one of the three); other keys ignored.
fn parse(body: &[u8]) -> Result<(String, String), &'static str> {
    let v: Value = serde_json::from_slice(body).map_err(|_| "body is not JSON")?;
    let o = v.as_object().ok_or("body is not a JSON object")?;
    let text = o.get("text").and_then(Value::as_str).ok_or("text must be a string")?;
    let op = o.get("op").and_then(Value::as_str).ok_or("op must be a string")?;
    if !(1..=MAX_TEXT).contains(&text.chars().count()) {
        return Err("text must be 1-4096 characters");
    }
    if !matches!(op, "upper" | "reverse" | "sha256") {
        return Err("unknown op");
    }
    Ok((text.to_owned(), op.to_owned()))
}

// ---------------------------------------------------------------- settings

struct Env {
    problems: Vec<String>,
}

impl Env {
    fn str(&self, name: &str, default: &str) -> String {
        std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_owned())
    }
    fn required(&mut self, name: &str) -> String {
        let v = std::env::var(name).unwrap_or_default();
        if v.is_empty() {
            self.problems.push(name.to_owned());
        }
        v
    }
    fn num(&mut self, name: &str, default: f64) -> f64 {
        match std::env::var(name).ok().filter(|v| !v.is_empty()) {
            None => default,
            Some(v) => v.parse().unwrap_or_else(|_| {
                self.problems.push(format!("{name} (not a number)"));
                default
            }),
        }
    }
    fn flag(&mut self, name: &str, default: bool) -> bool {
        match std::env::var(name).unwrap_or_default().as_str() {
            "" => default,
            "1" | "true" => true,
            "0" | "false" => false,
            _ => {
                self.problems.push(format!("{name} (0 or 1)"));
                default
            }
        }
    }
    fn list(&self, name: &str) -> Vec<String> {
        std::env::var(name)
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

fn home(p: &str) -> PathBuf {
    match (p.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(h)) => PathBuf::from(h).join(rest),
        _ => PathBuf::from(p),
    }
}

fn secs(f: f64) -> Duration {
    Duration::from_secs_f64(f.max(0.0))
}

struct Settings {
    netuid: u16,
    hotkey_file: PathBuf,
    bind: SocketAddr,
    external_ip: String,
    external_port: u16,
    auto_serve: bool,
    sidecar: SidecarConfig,
    ip_limit: RateLimit,
    hotkey_limit: RateLimit,
    max_age: Duration,
    skew: Duration,
    retention: Duration,
    redis_url: Option<String>,
    stream: Result<StreamLimits, String>,
    streams_per_caller: usize,
}

fn load() -> Result<Settings, String> {
    let mut e = Env { problems: Vec::new() };
    let netuid = e.num("TW_NETUID", -1.0);
    if !(0.0..=65_535.0).contains(&netuid) {
        e.problems.push("TW_NETUID".into());
    }
    let wallet = e.required("TW_WALLET_NAME");
    let hotkey_file = home(&e.str("TW_WALLET_PATH", "~/.bittensor/wallets"))
        .join(wallet)
        .join("hotkeys")
        .join(e.str("TW_WALLET_HOTKEY", "default"));
    let port = e.num("TW_BIND_PORT", 8091.0) as u16;
    let bind = format!("{}:{port}", e.str("TW_BIND_HOST", "0.0.0.0"))
        .parse()
        .map_err(|_| "TW_BIND_HOST must be an IP address".to_owned())?;
    let external_ip = e.required("TW_EXTERNAL_IP");
    let external_port = e.num("TW_EXTERNAL_PORT", f64::from(port)) as u16;
    let auto_serve = e.flag("TW_AUTO_SERVE_AXON", true);
    let state = e.str("TW_STATE_DIR", "~/.taowire");
    let token = e.str("TW_SIDECAR_TOKEN_FILE", &format!("{state}/sidecar.token"));
    let policy = CallerPolicy::new(
        e.flag("TW_REQUIRE_PERMIT", true),
        e.num("TW_MIN_CALLER_STAKE_TAO", 0.0),
        e.list("TW_ALLOW_HOTKEYS"),
        e.list("TW_DENY_HOTKEYS"),
    );
    let policy = policy.unwrap_or_else(|p| {
        e.problems.push(p);
        CallerPolicy::default()
    });
    let soft = e.num("TW_METAGRAPH_SOFT_AGE_S", 0.0);
    let max = e.num("TW_METAGRAPH_MAX_AGE_S", 0.0);
    let sidecar = SidecarConfig {
        url: format!("http://127.0.0.1:{}", e.num("TW_SIDECAR_PORT", 9910.0) as u16),
        token_file: Some(home(&token)),
        policy,
        strict: e.flag("TW_METAGRAPH_STRICT", false),
        soft_age: (soft > 0.0).then(|| secs(soft)),
        max_age: (max > 0.0).then(|| secs(max)),
        ..SidecarConfig::new(netuid as u16)
    };
    let s = Settings {
        netuid: netuid as u16,
        hotkey_file,
        bind,
        external_ip,
        external_port,
        auto_serve,
        sidecar,
        ip_limit: RateLimit {
            per_s: e.num("TW_RATE_IP_PER_S", 50.0),
            burst: e.num("TW_RATE_IP_BURST", 100.0),
        },
        hotkey_limit: RateLimit {
            per_s: e.num("TW_RATE_HOTKEY_PER_S", 20.0),
            burst: e.num("TW_RATE_HOTKEY_BURST", 40.0),
        },
        max_age: secs(e.num("TW_AUTH_MAX_AGE_S", 10.0)),
        skew: secs(e.num("TW_AUTH_ALLOWED_SKEW_S", 2.0)),
        retention: secs(e.num("TW_NONCE_RETENTION_S", 60.0)),
        redis_url: std::env::var("TW_REDIS_URL").ok().filter(|v| !v.is_empty()),
        stream: StreamLimits::new(
            secs(e.num("TW_STREAM_MAX_S", 60.0)),
            e.num("TW_STREAM_MAX_BYTES", 4_194_304.0) as u64,
            secs(e.num("TW_STREAM_IDLE_S", 10.0)),
        ),
        streams_per_caller: e.num("TW_STREAM_MAX_PER_CALLER", 16.0) as usize,
    };
    if e.problems.is_empty() {
        Ok(s)
    } else {
        Err(format!("settings: {}", e.problems.join(", ")))
    }
}

// ---------------------------------------------------------------- server

struct App {
    auth: Arc<MinerAuth>,
    sidecar: Arc<SidecarClient>,
    hotkeys: TokenBuckets,
    stream: StreamConfig,
}

fn log(event: &str, fields: Value) {
    let mut line = json!({"event": event});
    if let (Some(l), Some(f)) = (line.as_object_mut(), fields.as_object()) {
        l.extend(f.clone());
    }
    println!("{line}");
}

fn retry_after(mut resp: Response, wait: u64) -> Response {
    if let Ok(v) = HeaderValue::from_str(&wait.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

/// The per-hotkey limit (signed 429: inside `protect`) and the body checks.
fn admit(
    app: &App,
    caller: &Caller,
    route: &str,
    body: &[u8],
) -> Result<(String, String), Box<Response>> {
    let wait = app.hotkeys.take(&format!("{} {route}", caller.hotkey));
    if wait > 0 {
        let limited = error_response(&Error::new(codes::RATE_LIMITED, "per-hotkey limit"));
        return Err(Box::new(retry_after(limited, wait)));
    }
    parse(body).map_err(|why| Box::new(error_response(&Error::new("tw.invalid_request", why))))
}

async fn transform(
    State(app): State<Arc<App>>,
    Extension(caller): Extension<Caller>,
    body: Bytes,
) -> Response {
    match admit(&app, &caller, ROUTE, &body) {
        Ok((text, op)) => Json(json!({"result": expected(&text, &op)})).into_response(),
        Err(resp) => *resp,
    }
}

async fn transform_stream(
    State(app): State<Arc<App>>,
    Extension(caller): Extension<Caller>,
    Extension(ctx): Extension<StreamContext>,
    body: Bytes,
) -> Response {
    let (text, op) = match admit(&app, &caller, STREAM_ROUTE, &body) {
        Ok(req) => req,
        Err(resp) => return *resp,
    };
    let chars: Vec<char> = expected(&text, &op).chars().collect();
    let pieces: Vec<Result<Vec<u8>, BoxError>> = chars
        .chunks(PIECE_CHARS)
        .enumerate()
        .map(|(i, p)| {
            Ok(serde_json::to_vec(&json!({"i": i, "piece": p.iter().collect::<String>()}))?)
        })
        .collect();
    stream_response(&ctx, &app.stream, futures_util::stream::iter(pieces)).await
}

async fn ready(State(app): State<Arc<App>>) -> Response {
    let mut reasons = Vec::new();
    if app.sidecar.stage() == Stage::KnownCallersOnly {
        reasons.push("metagraph_stale");
    }
    if app.auth.verifier().failing_closed() {
        reasons.push("clock_step");
    }
    let body = Json(json!({"ready": reasons.is_empty(), "reasons": reasons}));
    if reasons.is_empty() {
        body.into_response()
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, body).into_response()
    }
}

/// The pre-auth per-IP limit (spec 8.6.2 layer 1): 429, unsigned.
async fn ip_limit(
    State(buckets): State<Arc<TokenBuckets>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let wait = buckets.take(&peer.ip().to_string());
    if wait > 0 {
        return retry_after(error_response(&Error::new(codes::RATE_LIMITED, "per-IP limit")), wait);
    }
    next.run(req).await
}

/// Serve the axon through the sidecar unless the snapshot already shows it; a
/// refusal is logged and the miner keeps serving.
async fn publish(sidecar: &SidecarClient, hotkey: &str, ip: &str, port: u16) {
    let want = format!("{ip}:{port}");
    if sidecar.snapshot().and_then(|s| s.by_hotkey(hotkey).and_then(|n| n.axon.clone())).as_deref()
        == Some(&want)
    {
        log("axon_in_sync", json!({"external": want}));
        return;
    }
    match sidecar.serve_axon(ip, port, None).await {
        Ok(hash) => log("axon_published", json!({"external": want, "block_hash": hash})),
        Err(ServeAxonError::Chain { code, remediation, .. }) => {
            log("serve_axon_rejected", json!({"code": code, "remediation": remediation}));
        }
        Err(ServeAxonError::Other(e)) => log("serve_axon_failed", json!({"code": e.code})),
    }
}

async fn run() -> Result<(), String> {
    let s = load()?;
    let key = Keypair::from_hotkey_file(&s.hotkey_file, Scheme::Sr25519)?;
    let hotkey = key.ss58().to_owned();
    let store: Arc<dyn NonceStore> = match &s.redis_url {
        Some(url) => {
            Arc::new(RedisStore::connect(url, s.retention, None).await.map_err(|e| e.to_string())?)
        }
        None => Arc::new(MemoryStore::new(s.retention)),
    };
    let cfg =
        Config { max_age: s.max_age, allowed_skew: s.skew, ..Config::new(hotkey.clone(), store) };
    let verifier = Verifier::new(cfg)?;
    let sidecar_url = s.sidecar.url.clone();
    let sidecar = Arc::new(SidecarClient::new(SidecarConfig {
        expected_hotkey: Some(hotkey.clone()),
        ..s.sidecar
    })?);
    sidecar.start().await.map_err(|e| format!("sidecar at {sidecar_url}: {e}"))?;
    if s.auto_serve {
        publish(&sidecar, &hotkey, &s.external_ip, s.external_port).await;
    }
    let limits = s.stream.map_err(|e| format!("TW_STREAM_*: {e}"))?;
    let slots = StreamSlots::new(s.streams_per_caller)
        .map_err(|e| format!("TW_STREAM_MAX_PER_CALLER: {e}"))?;
    let on_abort = Arc::new(|route: &str, reason: &str| {
        log("stream_aborted", json!({"route": route, "reason": reason}))
    });
    let stream = StreamConfig {
        limits,
        first_chunk_timeout: TIMEOUT,
        slots: Arc::new(slots),
        route: STREAM_ROUTE.into(),
        on_abort: Some(on_abort),
    };
    let auth = Arc::new(
        MinerAuth::new(verifier)
            .with_max_body_bytes(MAX_BODY)
            .with_response_key(key)
            .with_policy(sidecar.policy()),
    );
    let hotkeys =
        TokenBuckets::new(s.hotkey_limit).map_err(|e| format!("TW_RATE_HOTKEY_*: {e}"))?;
    let ips = Arc::new(TokenBuckets::new(s.ip_limit).map_err(|e| format!("TW_RATE_IP_*: {e}"))?);
    let app =
        Arc::new(App { auth: Arc::clone(&auth), sidecar: Arc::clone(&sidecar), hotkeys, stream });
    let protected = Router::new()
        .route(ROUTE, post(transform))
        .route(STREAM_ROUTE, post(transform_stream))
        .with_state(Arc::clone(&app))
        .layer(axum::middleware::from_fn_with_state(auth, protect));
    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(ready))
        .with_state(app)
        .merge(protected)
        .layer(axum::middleware::from_fn_with_state(ips, ip_limit));
    let listener = TcpListener::bind(s.bind).await.map_err(|e| e.to_string())?;
    log("miner_started", json!({"bind": s.bind.to_string(), "hotkey": hotkey, "netuid": s.netuid}));
    serve(listener, router, s.max_age + s.skew).await;
    Ok(())
}

/// Serves `router` until ctrl-c, then waits for open requests to finish.
///
/// `axum::serve` sets no header read timeout, so a client sending one header
/// byte at a time could hold a connection for as long as it likes. Here
/// hyper closes a connection whose request line and headers (or, between
/// keep-alive requests, the next request's) have not all arrived within
/// `header_timeout` (G7-2).
async fn serve(listener: TcpListener, router: Router, header_timeout: Duration) {
    let graceful = GracefulShutdown::new();
    let mut stop = std::pin::pin!(tokio::signal::ctrl_c());
    loop {
        let (tcp, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    // e.g. out of file descriptors: back off instead of spinning
                    log("accept_failed", json!({"error": e.to_string()}));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = &mut stop => break,
        };
        let router = router.clone();
        let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
            // what into_make_service_with_connect_info provided (the per-IP limit reads it)
            req.extensions_mut().insert(ConnectInfo(peer));
            router.clone().oneshot(req.map(axum::body::Body::new))
        });
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(header_timeout)
            .serve_connection(TokioIo::new(tcp), service);
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            // a closed or timed-out connection is routine; nothing to report
            let _ = conn.await;
        });
    }
    graceful.shutdown().await;
}

#[tokio::main]
async fn main() {
    if let Err(reason) = run().await {
        log("startup_refused", json!({"reason": reason}));
        std::process::exit(1);
    }
}
