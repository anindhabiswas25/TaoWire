//! Sidecar client (spec 11.6, 8.5, 8.5.1) against a fake sidecar, and the
//! policy hook of the axum layer.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ::axum::body::{Body, Bytes};
use ::axum::http::{HeaderMap, Request, StatusCode, Uri};
use ::axum::response::Response;
use ::axum::Router;
use serde_json::{json, Value};
use taowire_btauth::axum::{protect, MinerAuth};
use taowire_btauth::sidecar::{
    is_loopback, parse_decision, parse_health, parse_snapshot, read_token_file, CallerPolicy,
    Config as SidecarConfig, Decision, ServeAxonError, SidecarClient, Stage, MAX_ANSWER_BYTES,
};
use taowire_btauth::*;
use tower::ServiceExt;

const ALICE: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
const BOB: &str = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
const CHARLIE: &str = "5FA9nQDVg267DEd8m1ZypXLBnvN7SFxYwV7ndqSYGiN9TTpu";
const DAVE: &str = "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy";
const TOKEN: &str = "tttttttttttttttttttttttttttttttt";

fn neuron(uid: u16, hotkey: &str, permit: bool, stake: f64) -> Value {
    let axon = if uid == 0 { Value::Null } else { json!("203.0.113.7:8091") };
    json!({"uid": uid, "hotkey": hotkey, "validator_permit": permit, "total_stake_tao": stake, "axon": axon})
}

fn snapshot_body(age: f64, tempo: u16) -> Value {
    json!({"netuid": 2, "block": 100, "tempo": tempo, "age_s": age,
           "neurons": [neuron(0, ALICE, true, 1000.0), neuron(1, BOB, false, 5.0), neuron(2, CHARLIE, true, 10.0)]})
}

type Handler = Arc<dyn Fn(&Uri) -> (u16, Vec<u8>) + Send + Sync>;

#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<(String, String, String)>>>);

fn default_handler() -> Handler {
    Arc::new(|uri: &Uri| {
        match uri.path() {
        "/v1/health" => (
            200,
            json!({"ok": true, "hotkey": BOB, "netuid": 2, "block": 100, "metagraph_age_s": 1, "stage": "fresh"})
                .to_string()
                .into_bytes(),
        ),
        "/v1/metagraph" => (200, snapshot_body(1.0, 360).to_string().into_bytes()),
        _ => (404, b"nope".to_vec()),
    }
    })
}

async fn fake(handler: Handler) -> (String, Seen) {
    let seen = Seen::default();
    let log = seen.clone();
    let app = Router::new().fallback(move |headers: HeaderMap, uri: Uri, body: Bytes| {
        let (handler, log) = (Arc::clone(&handler), log.clone());
        async move {
            let auth =
                headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
            let path = uri.path_and_query().map_or_else(String::new, |p| p.to_string());
            log.0.lock().unwrap().push((
                auth.clone(),
                path,
                String::from_utf8_lossy(&body).into_owned(),
            ));
            let (status, out) = if auth == format!("Bearer {TOKEN}") {
                handler(&uri)
            } else {
                (401, error_body(&Error::new(codes::SIDECAR_UNAUTHORIZED, ""), None))
            };
            let mut r = Response::new(Body::from(out));
            *r.status_mut() = StatusCode::from_u16(status).unwrap();
            r
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { ::axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

fn config(url: &str) -> SidecarConfig {
    SidecarConfig { url: url.into(), token: Some(TOKEN.into()), ..SidecarConfig::new(2) }
}

fn client(url: &str, f: impl FnOnce(&mut SidecarConfig)) -> Arc<SidecarClient> {
    let mut c = config(url);
    f(&mut c);
    Arc::new(SidecarClient::new(c).unwrap())
}

#[test]
fn token_file() {
    let dir = std::env::temp_dir().join(format!("tw-sidecar-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, content: &[u8], mode: u32| {
        use std::os::unix::fs::PermissionsExt as _;
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    };
    let good = write("good", format!("{TOKEN}\n").as_bytes(), 0o600);
    assert_eq!(read_token_file(&good).unwrap(), TOKEN);
    let mut cases = vec![
        (write("open", TOKEN.as_bytes(), 0o644), "group or others"),
        (dir.join("missing"), "cannot open"),
        (dir.clone(), "not a regular file"),
    ];
    for (name, content) in [("empty", ""), ("short", "short"), ("space", "xxxxxxxxxxxxxxxxxxxx y")]
    {
        cases.push((write(name, content.as_bytes(), 0o600), "printable ASCII"));
    }
    cases.push((write("long", &[b'x'; 1025], 0o600), "printable ASCII"));
    cases.push((write("latin", b"xxxxxxxxxxxxxxxxxxxx\xe9", 0o600), "printable ASCII"));
    for (path, want) in cases {
        let e = read_token_file(&path).unwrap_err();
        assert!(e.contains(want) && !e.contains(TOKEN), "{}: {e}", path.display());
    }
    let c = SidecarClient::new(SidecarConfig { token_file: Some(good), ..SidecarConfig::new(2) })
        .unwrap();
    assert!(!format!("{c:?} {:?}", config("http://127.0.0.1:1")).contains(TOKEN));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn url_and_settings() {
    for u in [
        "http://127.0.0.1:9910",
        "http://127.0.0.2:1",
        "http://[::1]:9910",
        "http://localhost:9910",
    ] {
        assert!(is_loopback(&reqwest::Url::parse(u).unwrap()), "{u}");
    }
    for u in ["http://10.0.0.1:9910", "http://example.com", "http://[::2]"] {
        assert!(!is_loopback(&reqwest::Url::parse(u).unwrap()), "{u}");
        assert!(SidecarClient::new(config(u)).is_err(), "{u}");
    }
    assert!(SidecarClient::new(SidecarConfig {
        unsafe_allow_remote: true,
        ..config("http://10.0.0.1")
    })
    .is_ok());
    for bad in [
        config("ftp://127.0.0.1"),
        config("not a url"),
        SidecarConfig { token: Some("short".into()), ..config("http://127.0.0.1") },
        SidecarConfig {
            soft_age: Some(Duration::from_secs(60)),
            max_age: Some(Duration::from_secs(1)),
            ..config("http://127.0.0.1")
        },
        SidecarConfig { refresh: Duration::ZERO, ..config("http://127.0.0.1") },
        SidecarConfig { token: None, token_file: None, ..config("http://127.0.0.1") },
    ] {
        assert!(SidecarClient::new(bad).is_err());
    }
}

#[test]
fn policy() {
    let snap = parse_snapshot(snapshot_body(1.0, 360).to_string().as_bytes(), 2).unwrap();
    let code = |p: &CallerPolicy, h: &str| p.check(h, &snap).err().map_or("ok", |e| e.code);
    let strict = CallerPolicy::default();
    assert_eq!(code(&strict, ALICE), "ok");
    assert_eq!(code(&strict, BOB), "tw.forbidden_not_validator");
    assert_eq!(code(&strict, DAVE), "tw.forbidden_not_registered");
    let open = CallerPolicy::new(false, 0.0, [], []).unwrap();
    assert_eq!(code(&open, BOB), "ok");
    let staked = CallerPolicy::new(true, 100.0, [], []).unwrap();
    assert_eq!(code(&staked, CHARLIE), "tw.forbidden_low_stake");
    assert_eq!(code(&staked, ALICE), "ok");
    let lists = CallerPolicy::new(true, 0.0, [DAVE.into()], [ALICE.into()]).unwrap();
    assert_eq!(code(&lists, DAVE), "ok");
    assert_eq!(code(&lists, ALICE), "tw.forbidden_denied");
    for bad in [-1.0, f64::NAN, f64::INFINITY] {
        assert!(CallerPolicy::new(true, bad, [], []).is_err());
    }
    assert!(CallerPolicy::new(true, 0.0, [ALICE.into()], [ALICE.into()]).is_err());
}

#[tokio::test]
async fn calls() {
    let (url, seen) = fake(default_handler()).await;
    let c = client(&url, |_| {});
    c.start().await.unwrap();
    c.stop();
    let calls = seen.0.lock().unwrap().clone();
    assert_eq!(
        calls.iter().map(|c| c.1.as_str()).collect::<Vec<_>>(),
        ["/v1/health", "/v1/metagraph?netuid=2"]
    );
    assert!(calls.iter().all(|c| c.0 == format!("Bearer {TOKEN}")));
    let wrong = client(&url, |c| c.token = Some("w".repeat(32)));
    assert_eq!(wrong.health().await.unwrap_err().code, codes::SIDECAR_UNAUTHORIZED);
    assert!(client(&url, |c| c.expected_hotkey = Some(ALICE.into())).start().await.is_err());
    assert!(client(&url, |c| c.netuid = 3).start().await.is_err());
    let ok = client(&url, |c| c.expected_hotkey = Some(BOB.into()));
    ok.start().await.unwrap();
    ok.stop();
}

#[tokio::test]
async fn caller_and_serve_axon() {
    let hash = format!("0x{}", "ab".repeat(32));
    let answers = Arc::new(Mutex::new(vec![
        (200, json!({"allowed": true}).to_string().into_bytes()),
        (200, json!({"allowed": false, "code": "tw.forbidden_low_stake"}).to_string().into_bytes()),
        (200, json!({"ok": true, "block_hash": hash}).to_string().into_bytes()),
        (409, json!({"ok": false, "code": "rate_limited", "error_name": null, "remediation": "wait 50 blocks"}).to_string().into_bytes()),
        (503, json!({"ok": false, "code": "chain_unavailable"}).to_string().into_bytes()),
        (422, error_body(&Error::new("tw.invalid_request", ""), None)),
        (200, json!({"ok": true, "block_hash": "0x12"}).to_string().into_bytes()),
        (409, b"garbage".to_vec()),
        (503, error_body(&Error::new("tw.forbidden_denied", ""), None)),
    ]));
    let a = Arc::clone(&answers);
    let (url, seen) = fake(Arc::new(move |_: &Uri| a.lock().unwrap().remove(0))).await;
    let c = client(&url, |_| {});
    assert_eq!(c.caller(ALICE).await.unwrap(), Decision::Allowed);
    assert_eq!(c.caller("a/b c").await.unwrap(), Decision::Refused("tw.forbidden_low_stake"));
    assert_eq!(c.serve_axon("203.0.113.7", 8091, None).await.unwrap(), hash);
    let body: Value = serde_json::from_str(&seen.0.lock().unwrap()[2].2).unwrap();
    assert_eq!(body, json!({"netuid": 2, "ip": "203.0.113.7", "port": 8091, "tls_cert_hex": null}));
    match c.serve_axon("x", 1, Some("0x01ab")).await.unwrap_err() {
        ServeAxonError::Chain { code, remediation, .. } => {
            assert_eq!(
                (code.as_str(), remediation.as_deref()),
                ("rate_limited", Some("wait 50 blocks"))
            );
        }
        other => panic!("{other}"),
    }
    let chain = c.serve_axon("x", 1, None).await.unwrap_err();
    assert!(
        matches!(&chain, ServeAxonError::Chain { code, .. } if code == "chain_unavailable"),
        "{chain}"
    );
    for want in [
        "tw.invalid_request",
        codes::INVALID_RESPONSE,
        codes::INVALID_RESPONSE,
        codes::INVALID_RESPONSE,
    ] {
        match c.serve_axon("x", 1, None).await.unwrap_err() {
            ServeAxonError::Other(e) => assert_eq!(e.code, want),
            other => panic!("{other}"),
        }
    }
    let calls = seen.0.lock().unwrap().clone();
    assert_eq!(calls[1].1, "/v1/caller/a%2Fb%20c?netuid=2");
    assert_eq!(calls.len(), 9, "a write is never resent");
}

#[tokio::test]
async fn transport_failures() {
    let dead = client("http://127.0.0.1:1", |_| {});
    assert_eq!(dead.health().await.unwrap_err().code, codes::CONNECT_ERROR);
    let slow = Router::new().fallback(|| async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        "late"
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { ::axum::serve(listener, slow).await.unwrap() });
    let quick = client(&format!("http://{addr}"), |c| c.timeout = Duration::from_millis(200));
    assert_eq!(quick.health().await.unwrap_err().code, codes::TIMEOUT);
    let (big, _) = fake(Arc::new(|_: &Uri| (200, vec![b' '; MAX_ANSWER_BYTES + 1]))).await;
    assert_eq!(client(&big, |_| {}).health().await.unwrap_err().code, codes::RESPONSE_TOO_LARGE);
    let (stale, _) =
        fake(Arc::new(|_: &Uri| (503, error_body(&Error::new(codes::METAGRAPH_STALE, ""), None))))
            .await;
    assert_eq!(client(&stale, |_| {}).metagraph().await.unwrap_err().code, codes::METAGRAPH_STALE);
    assert_eq!(
        client(&stale, |_| {}).caller(ALICE).await.unwrap_err().code,
        codes::METAGRAPH_STALE
    );
    assert_eq!(client(&stale, |_| {}).start().await.unwrap_err().code, codes::METAGRAPH_STALE);
    let (redirect, _) = fake(Arc::new(|_: &Uri| (307, Vec::new()))).await;
    assert_eq!(client(&redirect, |_| {}).health().await.unwrap_err().code, codes::INVALID_RESPONSE);
}

#[tokio::test]
async fn stages_and_known_callers() {
    let state = Arc::new(Mutex::new((5.0_f64, false)));
    let s = Arc::clone(&state);
    let (url, _) = fake(Arc::new(move |_: &Uri| {
        let (age, fail) = *s.lock().unwrap();
        if fail {
            (500, b"down".to_vec())
        } else {
            (200, snapshot_body(age, 10).to_string().into_bytes()) // tempo 10: max 240 s, soft 120 s
        }
    }))
    .await;
    let base = Instant::now() + Duration::from_secs(100_000);
    let offset = Arc::new(Mutex::new(Duration::ZERO));
    let o = Arc::clone(&offset);
    let now: Arc<dyn Fn() -> Instant + Send + Sync> = Arc::new(move || base + *o.lock().unwrap());
    let advance = |d: u64| *offset.lock().unwrap() += Duration::from_secs(d);
    let c = client(&url, |c| c.now = Some(Arc::clone(&now)));
    let want = |h: &str, scope: &str, code: &str| {
        assert_eq!(c.check(h, scope).err().map_or("ok", |e| e.code), code, "{h} on {scope}");
    };
    assert_eq!(c.stage(), Stage::KnownCallersOnly);
    assert!(c.snapshot().is_none() && c.age().is_none());
    want(ALICE, "/r", codes::METAGRAPH_STALE);
    c.metagraph().await.unwrap();
    assert_eq!(c.thresholds(), (Duration::from_secs(120), Duration::from_secs(240)));
    want(ALICE, "/r", "ok");
    advance(115);
    assert_eq!(c.stage(), Stage::Degraded);
    advance(120);
    assert_eq!(c.stage(), Stage::Degraded, "exactly the max age is degraded");
    advance(1);
    assert_eq!(c.stage(), Stage::KnownCallersOnly);
    want(ALICE, "/r", "ok");
    want(ALICE, "/other", codes::METAGRAPH_STALE);
    want(CHARLIE, "/r", codes::METAGRAPH_STALE);
    state.lock().unwrap().0 = 241.0;
    c.metagraph().await.unwrap(); // the same stale snapshot again
    want(ALICE, "/r", "ok");
    state.lock().unwrap().0 = 238.0; // the same snapshot answered 3 s late is not newer
    c.metagraph().await.unwrap();
    want(ALICE, "/r", "ok");
    state.lock().unwrap().1 = true;
    assert!(
        c.metagraph().await.is_err() && c.snapshot().is_some(),
        "a failed refresh keeps the snapshot"
    );
    *state.lock().unwrap() = (0.0, false);
    c.metagraph().await.unwrap();
    assert_eq!((c.stage(), c.age()), (Stage::Fresh, Some(Duration::ZERO)));
    want(BOB, "/r", "tw.forbidden_not_validator");
    let strict = client(&url, |c| {
        c.strict = true;
        c.max_age = Some(Duration::from_secs(50));
        c.soft_age = Some(Duration::from_secs(10));
        c.now = Some(Arc::clone(&now));
    });
    strict.metagraph().await.unwrap();
    assert!(strict.check(ALICE, "/").is_ok());
    advance(60);
    assert_eq!(strict.check(ALICE, "/").unwrap_err().code, codes::METAGRAPH_STALE);
    let denied =
        client(&url, |c| c.policy = CallerPolicy::new(true, 0.0, [], [ALICE.into()]).unwrap());
    assert_eq!(denied.check(ALICE, "/").unwrap_err().code, "tw.forbidden_denied");
}

#[tokio::test]
async fn background_refresh() {
    let (url, seen) = fake(default_handler()).await;
    let c = client(&url, |c| c.refresh = Duration::from_millis(50));
    c.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    c.stop();
    let n = seen.0.lock().unwrap().len();
    assert!(n >= 4, "{n}");
    // Invented paths do not grow the known-callers set (one scope).
    let hook = c.policy();
    let caller = Caller { hotkey: ALICE.into(), nonce: 1, scheme: Scheme::Sr25519 };
    for i in 0..100 {
        hook(&caller, &format!("/x/{i}")).unwrap();
    }
    assert_eq!(c.known_callers(), 1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(seen.0.lock().unwrap().len(), n, "no refresh after stop");
}

#[test]
fn hostile_snapshots() {
    let with = |k: &str, v: Value| {
        let mut b = snapshot_body(1.0, 360);
        b[k] = v;
        b.to_string()
    };
    let with_neuron = |k: &str, v: Value| {
        let mut n = neuron(0, ALICE, true, 1.0);
        n[k] = v;
        with("neurons", json!([n]))
    };
    let missing = |k: &str| {
        let mut n = neuron(0, ALICE, true, 1.0);
        n.as_object_mut().unwrap().remove(k);
        with("neurons", json!([n]))
    };
    let cases = [
        with("netuid", json!(3)),
        with("netuid", json!("2")),
        with("netuid", json!(2.5)),
        with("block", json!(-1)),
        with("block", json!(1.5)),
        with("tempo", json!(0)),
        with("age_s", json!(-1)),
        with("age_s", json!("1")),
        with("neurons", json!({})),
        with("neurons", Value::Null),
        with("neurons", json!([null])),
        with("neurons", json!([neuron(0, ALICE, true, 1.0), neuron(0, BOB, true, 1.0)])),
        with("neurons", json!([neuron(0, ALICE, true, 1.0), neuron(1, ALICE, true, 1.0)])),
        with_neuron("hotkey", json!("5Grw")),
        with_neuron("validator_permit", json!(1)),
        with_neuron("total_stake_tao", json!(-5)),
        with_neuron("total_stake_tao", json!("1e9")),
        with_neuron("axon", json!(5)),
        missing("axon"),
        missing("uid"),
        json!([snapshot_body(1.0, 360)]).to_string(),
        r#"{"netuid":2,"netuid":2,"block":1,"tempo":1,"age_s":0,"neurons":[]}"#.into(),
        format!(
            r#"{{"netuid":2,"block":1,"tempo":1,"age_s":0,"neurons":[{{"uid":0,"uid":1,"hotkey":"{ALICE}","validator_permit":true,"total_stake_tao":1,"axon":null}}]}}"#
        ),
        "{}x".into(),
    ];
    for (i, body) in cases.iter().enumerate() {
        assert_eq!(
            parse_snapshot(body.as_bytes(), 2).unwrap_err().code,
            codes::INVALID_RESPONSE,
            "case {i}"
        );
    }
    assert!(parse_snapshot(b"\xff", 2).is_err());
    let s = parse_snapshot(snapshot_body(1.0, 360).to_string().as_bytes(), 2).unwrap();
    assert_eq!(s.neurons.len(), 3);
    assert_eq!(s.by_hotkey(BOB).map(|n| n.uid), Some(1));
    for body in [
        r#"{"allowed":"true"}"#,
        r#"{"allowed":1}"#,
        r#"{"allowed":true,"code":"tw.forbidden_denied"}"#,
        r#"{"allowed":false}"#,
        r#"{"allowed":false,"code":"tw.ok"}"#,
        r#"{"allowed":false,"allowed":true}"#,
        "[true]",
    ] {
        assert!(parse_decision(body.as_bytes()).is_err(), "{body}");
    }
    let h = json!({"ok": true, "hotkey": BOB, "netuid": 2, "block": null, "metagraph_age_s": null, "stage": "known_callers_only"});
    let got = parse_health(h.to_string().as_bytes()).unwrap();
    assert_eq!((got.block, got.metagraph_age_s, got.stage), (None, None, Stage::KnownCallersOnly));
    for (k, v) in [
        ("ok", json!("yes")),
        ("hotkey", json!("x")),
        ("stage", json!("stale")),
        ("block", json!(-1)),
        ("metagraph_age_s", json!(-1)),
        ("netuid", json!("2")),
    ] {
        let mut bad = h.clone();
        bad[k] = v;
        assert!(parse_health(bad.to_string().as_bytes()).is_err(), "{k}");
    }
    for k in ["block", "metagraph_age_s"] {
        let mut bad = h.clone();
        bad.as_object_mut().unwrap().remove(k);
        assert!(parse_health(bad.to_string().as_bytes()).is_err(), "without {k}");
    }
}

/// Arbitrary JSON (random trees, and mutations of a valid snapshot) never
/// admits a caller the answer does not really list with a permit.
#[test]
fn arbitrary_answers_fail_closed() {
    let mut state = 7u64;
    let mut rnd = move |n: u64| {
        state =
            state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) % n
    };
    let atoms = [
        json!(null),
        json!(true),
        json!(false),
        json!(0),
        json!(-1),
        json!(1.5),
        json!("x"),
        json!(ALICE),
        json!([]),
        json!({}),
    ];
    for _ in 0..5000 {
        let mut body = snapshot_body(1.0, 360);
        for _ in 0..=rnd(3) {
            let atom = atoms[rnd(atoms.len() as u64) as usize].clone();
            let keys = ["netuid", "block", "tempo", "age_s", "neurons"];
            if rnd(2) == 0 {
                body[keys[rnd(5) as usize]] = atom;
            } else if let Some(ns) = body["neurons"].as_array_mut() {
                if !ns.is_empty() {
                    let i = rnd(ns.len() as u64) as usize;
                    let nk = ["uid", "hotkey", "validator_permit", "total_stake_tao", "axon"];
                    ns[i][nk[rnd(5) as usize]] = atom;
                }
            }
        }
        let text = body.to_string();
        if let Ok(s) = parse_snapshot(text.as_bytes(), 2) {
            let listed = s.by_hotkey(ALICE).is_some_and(|n| n.validator_permit);
            assert_eq!(CallerPolicy::default().check(ALICE, &s).is_ok(), listed, "{text}");
        }
        let bytes: Vec<u8> = (0..rnd(40)).map(|_| rnd(256) as u8).collect();
        assert!(parse_snapshot(&bytes, 2).is_err());
        if let Ok(Decision::Allowed) = parse_decision(&bytes) {
            panic!("allowed {bytes:?}");
        }
    }
}

#[tokio::test]
async fn protect_runs_the_policy() {
    let key = Keypair::sr25519_from_seed(
        &hex::decode("398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let cases: Vec<(Error, u16, &str, bool)> = vec![
        (Error::new("tw.forbidden_not_validator", ""), 403, "tw.forbidden_not_validator", true),
        (Error::new(codes::METAGRAPH_STALE, ""), 503, codes::METAGRAPH_STALE, false),
        (Error::new(codes::TIMEOUT, "client code"), 500, codes::INTERNAL, false),
    ];
    for (err, status, code, signed) in cases {
        let store = Arc::new(MemoryStore::new(Duration::from_secs(60)));
        let verifier = Verifier::new(Config::new(key.ss58(), store)).unwrap();
        let seen_path = Arc::new(Mutex::new(String::new()));
        let p = Arc::clone(&seen_path);
        let policy: taowire_btauth::axum::PolicyFn = Arc::new(move |_c: &Caller, path: &str| {
            *p.lock().unwrap() = path.to_owned();
            Err(err.clone())
        });
        let k2 = Keypair::sr25519_from_seed(
            &hex::decode("398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let auth = Arc::new(MinerAuth::new(verifier).with_response_key(k2).with_policy(policy));
        let app = Router::new()
            .fallback(|| async { "ok" })
            .layer(::axum::middleware::from_fn_with_state(auth, protect));
        let (headers, _) = Signer::new(Keypair::sr25519_from_seed(
            &hex::decode("e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a")
                .unwrap()
                .try_into()
                .unwrap(),
        ))
        .sign("POST", "/v1/x?y=1", b"", Some(key.ss58()));
        let mut req = Request::builder().method("POST").uri("/v1/x?y=1");
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status().as_u16(), status);
        assert_eq!(resp.headers().contains_key("x-tw-resp-signature"), signed, "{code}");
        let body = ::axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains(code));
        assert_eq!(*seen_path.lock().unwrap(), "/v1/x");
    }
}
