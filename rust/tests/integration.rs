//! Everything besides the vectors: keys, nonces, stores, verifier settings,
//! the axum layer and the reqwest client against a live local server.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ::axum::body::{Body, Bytes};
use ::axum::http::{Request, StatusCode};
use ::axum::routing::post;
use ::axum::{Extension, Router};
use tensorwire_btauth::axum::{error_response, protect, MinerAuth};
use tensorwire_btauth::client::Client;
use tensorwire_btauth::redis_store::RedisStore;
use tensorwire_btauth::*;
use tower::ServiceExt;

fn seed(h: &str) -> [u8; 32] {
    hex::decode(h).unwrap().try_into().unwrap()
}
// Public dev keys //Alice, //Bob (sr25519) and //Alice (ed25519).
fn alice() -> Keypair {
    Keypair::sr25519_from_seed(&seed(
        "e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a",
    ))
}
fn bob() -> Keypair {
    Keypair::sr25519_from_seed(&seed(
        "398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89",
    ))
}
fn alice_ed() -> Keypair {
    Keypair::ed25519_from_seed(&seed(
        "abf8e5bdbe30c65656c0a3cbd181ff8a56294a69dfedd27982aace4a76909115",
    ))
}

fn verifier() -> Verifier {
    Verifier::new(Config::new(bob().ss58(), Arc::new(MemoryStore::new(Duration::from_secs(60)))))
        .unwrap()
}

fn borrowed(p: &[(String, String)]) -> Vec<(&str, &str)> {
    p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

#[test]
fn appendix_c_and_d() {
    assert_eq!(alice().ss58(), "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY");
    assert_eq!(alice_ed().ss58(), "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu");
    let payload = build_payload(
        Scheme::Ed25519,
        "POST",
        "/generate?stream=false",
        br#"{"prompt": "hello"}"#,
        1_752_076_800_000_000_000,
        alice_ed().ss58(),
        Some(bob().ss58()),
    );
    assert_eq!(hex::encode(alice_ed().sign(&payload)), "1a6b631988bf1f7ea093ab9d5acf61f05c316d0b0e428b24b487b75a5f6ee0e1a56a26918fdf871b6cf09437e6588023a4ce423cf622621b2a7feee17612f704");
    let dbg = format!("{:?}", alice());
    assert!(dbg.contains(alice().ss58()) && !dbg.contains("e5be"));
    assert_eq!(Scheme::Ed25519.as_str(), "ed25519");
}

#[test]
fn ss58_and_weak_keys() {
    assert_eq!(decode_ss58(&encode_ss58(&alice().public_key())), Some(alice().public_key()));
    for bad in ["", "0", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ"] {
        assert_eq!(decode_ss58(bad), None, "{bad}");
    }
    assert!(is_weak_public_key(Scheme::Sr25519, &[0; 32]));
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(is_weak_public_key(Scheme::Ed25519, &identity));
    assert!(!is_weak_public_key(Scheme::Ed25519, &alice_ed().public_key()));
    assert!(!is_weak_public_key(Scheme::Ed25519, &[0xff; 32]));
}

#[test]
fn nonces_strictly_increase_across_threads() {
    let n = Arc::new(NonceSource::with_clock(|| 1000));
    assert_eq!((n.next(), n.next()), (1000, 1001));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let n = n.clone();
            std::thread::spawn(move || (0..1000).map(|_| n.next()).collect::<Vec<_>>())
        })
        .collect();
    let mut all: Vec<u64> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let len = all.len();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), len);
    assert!(NonceSource::default().next() > 1_700_000_000_000_000_000);
    assert!(format!("{n:?}").starts_with("NonceSource"));
}

#[test]
fn memory_store_expires() {
    let s = MemoryStore::new(Duration::from_secs(10));
    let t0 = Instant::now();
    assert!(s.is_empty());
    assert!(s.check_and_store_at("a", 1, t0));
    assert!(!s.check_and_store_at("a", 1, t0));
    assert!(s.check_and_store_at("b", 1, t0));
    assert_eq!(s.len(), 2);
    assert!(s.check_and_store_at("a", 1, t0 + Duration::from_secs(11)));
    assert_eq!(s.len(), 1);
    assert_eq!(NonceStore::retention(&s), Duration::from_secs(10));
    assert!(format!("{s:?}").contains("10s"));
}

#[test]
fn verifier_settings_are_validated() {
    let store = || Arc::new(MemoryStore::new(Duration::from_secs(60)));
    assert!(Verifier::new(Config::new("nope", store())).is_err());
    let mut short = Config::new(bob().ss58(), Arc::new(MemoryStore::new(Duration::from_secs(5))));
    short.max_age = Duration::from_secs(10);
    assert!(Verifier::new(short).is_err());
    let mut zero = Config::new(bob().ss58(), store());
    zero.allowed_skew = Duration::ZERO;
    assert!(Verifier::new(zero).is_err());
    let v = verifier();
    assert_eq!(v.self_hotkey(), bob().ss58());
    assert!(format!("{v:?}").contains(bob().ss58()));
}

#[test]
fn errors_follow_appendix_a() {
    let e = Error::new("tw.nonsense", "x");
    assert_eq!((e.code, e.status), ("tw.internal", 500));
    assert_eq!(Error::new(codes::TIMEOUT, "").status, 0);
    assert_eq!(status_of("tw.forbidden_low_stake"), 403);
    assert_eq!(status_of("x"), 500);
    let body: serde_json::Value =
        serde_json::from_slice(&error_body(&Error::new(codes::STALE, "d"), Some("01J"))).unwrap();
    assert_eq!(body["error"]["code"], codes::STALE);
    assert_eq!(body["error"]["request_id"], "01J");
    assert!(Error::new(codes::STALE, "detail").to_string().contains("detail"));
    assert!(Error::new(codes::STALE, "").to_string().contains("freshness"));
}

struct DownStore;
impl NonceStore for DownStore {
    fn check_and_store<'a>(&'a self, _: &'a str, _: u64) -> StoreFuture<'a> {
        Box::pin(async { Err(StoreError("redis down".into())) })
    }
    fn retention(&self) -> Duration {
        Duration::from_secs(60)
    }
}

#[tokio::test]
async fn store_outage_fails_closed_and_replays_are_refused() {
    let v = Verifier::new(Config::new(bob().ss58(), Arc::new(DownStore))).unwrap();
    let (h, _) = Signer::new(alice()).sign("POST", "/x", b"", Some(bob().ss58()));
    let e = v.verify(borrowed(&h), b"", "POST", "/x").await.unwrap_err();
    assert_eq!((e.code, e.status), (codes::REPLAY_STORE_UNAVAILABLE, 503));
    let v = verifier();
    v.verify(borrowed(&h), b"", "POST", "/x").await.unwrap();
    assert_eq!(v.verify(borrowed(&h), b"", "POST", "/x").await.unwrap_err().code, codes::REPLAYED);
}

/// Base58 decoding is quadratic and runs before the signature check.
#[tokio::test]
async fn huge_sender_is_refused_before_decoding() {
    let (mut h, _) = Signer::new(alice()).sign("POST", "/x", b"", Some(bob().ss58()));
    for (k, v) in &mut h {
        if k == "X-Bittensor-Hotkey" {
            *v = "z".repeat(1 << 20);
        }
    }
    let start = Instant::now();
    let e = verifier().verify(borrowed(&h), b"", "POST", "/x").await.unwrap_err();
    assert_eq!(e.code, codes::MALFORMED);
    assert!(start.elapsed() < Duration::from_millis(100), "{:?}", start.elapsed());
}

#[test]
fn twresp_rejections() {
    let h = sign_response(&bob(), 7, alice().ss58(), 200, b"ok");
    let ok = |h: &[(String, String)], who: &str| {
        verify_response(borrowed(h), who, 7, alice().ss58(), 200, b"ok").is_ok()
    };
    assert!(ok(&h, bob().ss58()));
    assert!(!ok(&h, "nope"));
    let mut dup = h.clone();
    dup.push(("x-tw-resp-signature".into(), h[2].1.clone()));
    assert!(!ok(&dup, bob().ss58()));
    let mut v2 = h.clone();
    v2[0].1 = "2".into();
    assert!(!ok(&v2, bob().ss58()));
    let mut scheme = h.clone();
    scheme.push(("X-TW-Resp-Crypto".into(), "ecdsa".into()));
    assert!(!ok(&scheme, bob().ss58()));
}

// ------------------------------------------------------------------ axum

async fn echo(Extension(caller): Extension<Caller>, body: Bytes) -> (StatusCode, String) {
    (StatusCode::CREATED, format!("{}:{}", caller.hotkey, String::from_utf8_lossy(&body)))
}

async fn refuse() -> ::axum::response::Response {
    error_response(&Error::new("tw.forbidden_not_validator", ""))
}

fn app(auth: MinerAuth) -> Router {
    Router::new()
        .route("/{*path}", post(echo))
        .route("/forbidden", post(refuse))
        .layer(::axum::middleware::from_fn_with_state(Arc::new(auth), protect))
}

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { ::axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap()
}

#[tokio::test]
async fn client_and_layer_round_trip() {
    let url = serve(app(MinerAuth::new(verifier()).with_response_key(bob()))).await;
    let client = Client::new(Signer::new(alice()), http());
    for target in ["/a%20b?x=%2F", "/p?", "/plain"] {
        let r = client
            .send(
                reqwest::Method::POST,
                &format!("{url}{target}"),
                br#"{"q":1}"#.to_vec(),
                bob().ss58(),
            )
            .await
            .unwrap_or_else(|e| panic!("{target}: {e}"));
        assert_eq!(r.status, 201, "{target}");
        assert_eq!(r.body, format!(r#"{}:{{"q":1}}"#, alice().ss58()).into_bytes());
        assert_eq!(r.scheme, Scheme::Sr25519);
    }
    let r =
        client.send(reqwest::Method::POST, &format!("{url}/forbidden"), vec![], bob().ss58()).await;
    assert_eq!(r.unwrap().status, 403, "signed handler errors verify too");
}

#[tokio::test]
async fn unsigned_answers_do_not_verify_and_network_errors_map() {
    let url = serve(app(MinerAuth::new(verifier()))).await;
    let client = Client::new(Signer::new(alice_ed()), http());
    let e = client.send(reqwest::Method::PUT, &format!("{url}/x"), vec![], bob().ss58()).await;
    assert_eq!(e.unwrap_err().code, codes::BAD_RESPONSE_SIGNATURE);
    let e = client.send(reqwest::Method::GET, "http://127.0.0.1:1/x", vec![], bob().ss58()).await;
    assert_eq!(e.unwrap_err().code, codes::CONNECT_ERROR);
    let e = client.send(reqwest::Method::GET, "::bad", vec![], bob().ss58()).await;
    assert_eq!(e.unwrap_err().code, codes::CONNECT_ERROR);
    let slow = serve(Router::new().route(
        "/s",
        post(|| async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            "late"
        }),
    ))
    .await;
    let quick = reqwest::Client::builder().timeout(Duration::from_millis(200)).build().unwrap();
    let e = Client::new(Signer::new(alice()), quick)
        .send(reqwest::Method::POST, &format!("{slow}/s"), vec![], bob().ss58())
        .await;
    assert_eq!(e.unwrap_err().code, codes::TIMEOUT);
    let big = serve(Router::new().route("/b", post(|| async { "0123456789" }))).await;
    let e = Client::new(Signer::new(alice()), http())
        .with_max_response_bytes(4)
        .send(reqwest::Method::POST, &format!("{big}/b"), vec![], bob().ss58())
        .await;
    assert_eq!(e.unwrap_err().code, codes::RESPONSE_TOO_LARGE);
}

async fn status_and_code(router: Router, req: Request<Body>) -> (u16, String) {
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    assert!(resp.headers().get("x-tw-resp-signature").is_none(), "refusals are unsigned");
    let body = ::axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, v["error"]["code"].as_str().unwrap().to_owned())
}

fn signed(target: &str, body: &[u8]) -> ::axum::http::request::Builder {
    let (h, _) = Signer::new(alice()).sign("POST", target, body, Some(bob().ss58()));
    h.into_iter().fold(Request::post(target), |b, (k, v)| b.header(k, v))
}

#[tokio::test]
async fn layer_refusals() {
    let app = || app(MinerAuth::new(verifier()).with_max_body_bytes(8).with_response_key(bob()));
    let cases = [
        (Request::post("/x").body(Body::empty()).unwrap(), 401, codes::MALFORMED),
        (
            signed("/x", b"0123456789").body(Body::from("0123456789")).unwrap(),
            413,
            codes::PAYLOAD_TOO_LARGE,
        ),
        (
            signed("/x", b"").header("content-length", "999").body(Body::empty()).unwrap(),
            413,
            codes::PAYLOAD_TOO_LARGE,
        ),
        (signed("/x", b"a").body(Body::from("b")).unwrap(), 401, codes::BAD_SIGNATURE),
        (
            Request::post("http://evil.example/x").body(Body::empty()).unwrap(),
            401,
            codes::MALFORMED,
        ),
        (
            signed("/x", b"")
                .header("x-bittensor-version", &b"\xff"[..])
                .body(Body::empty())
                .unwrap(),
            401,
            codes::MALFORMED,
        ),
    ];
    for (i, (req, status, code)) in cases.into_iter().enumerate() {
        assert_eq!(status_and_code(app(), req).await, (status, code.to_owned()), "case {i}");
    }
    // A chunked body over the limit (no Content-Length).
    let stream = futures_util::stream::iter(
        [Bytes::from_static(b"0123456"), Bytes::from_static(b"789")].map(Ok::<_, std::io::Error>),
    );
    let req = signed("/x", b"0123456789").body(Body::from_stream(stream)).unwrap();
    assert_eq!(status_and_code(app(), req).await, (413, codes::PAYLOAD_TOO_LARGE.to_owned()));
}

#[test]
#[should_panic(expected = "response key must be the miner hotkey")]
fn response_key_must_match() {
    let _ = MinerAuth::new(verifier()).with_response_key(alice());
}

// ----------------------------------------------------------------- redis

#[tokio::test]
async fn redis_store() {
    assert!(RedisStore::connect("redis://127.0.0.1:6379", Duration::ZERO, None).await.is_err());
    assert!(RedisStore::connect("not a url", Duration::from_secs(1), None).await.is_err());
    let Ok(url) = std::env::var("TENSORWIRE_TEST_REDIS_URL") else {
        return; // real Redis only when the Python suite's variable is set
    };
    let prefix = format!("tw:test:rust:{}:", NonceSource::new().next());
    let s = RedisStore::connect(&url, Duration::from_secs(2), Some(&prefix)).await.unwrap();
    assert!(s.check_and_store("5Grw", 42).await.unwrap());
    assert!(!s.check_and_store("5Grw", 42).await.unwrap());
    assert_eq!(s.retention(), Duration::from_secs(2));
    assert!(format!("{s:?}").contains(&prefix));
}
