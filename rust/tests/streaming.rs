//! SSE streaming with a signed trailer (spec 9.2, D29, D35, D36): the shared
//! pieces, the axum `stream_response` and the reqwest `Client::stream`.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ::axum::body::{Body, Bytes};
use ::axum::extract::Request;
use ::axum::http::HeaderMap;
use ::axum::response::Response;
use ::axum::{Extension, Router};
use futures_util::stream;
use taowire_btauth::axum::{
    protect, stream_response, BoxError, MinerAuth, StreamConfig, StreamContext,
};
use taowire_btauth::client::Client;
use taowire_btauth::sse::*;
use taowire_btauth::*;

fn seed(h: &str) -> [u8; 32] {
    hex::decode(h).unwrap().try_into().unwrap()
}
const BOB_SEED: &str = "398f0c28f98885e046333d4a41c19cee4c37368a9832c6502f6cfd182e2aef89";
fn alice() -> Keypair {
    Keypair::sr25519_from_seed(&seed(
        "e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a",
    ))
}
fn alice_ed() -> Keypair {
    Keypair::ed25519_from_seed(&seed(
        "abf8e5bdbe30c65656c0a3cbd181ff8a56294a69dfedd27982aace4a76909115",
    ))
}
fn bob() -> Keypair {
    Keypair::sr25519_from_seed(&seed(BOB_SEED))
}

fn parse_all(input: &[u8]) -> Vec<Event> {
    let mut p = Parser::new();
    let mut out = p.feed(input);
    out.extend(p.finish());
    out
}

fn ev(event: &str, data: &str) -> Event {
    Event { event: event.into(), data: data.as_bytes().to_vec() }
}

#[test]
fn parser_cases() {
    let cases: &[(&str, Vec<Event>)] = &[
        ("event: chunk\ndata: {}\n\n", vec![ev("chunk", "{}")]),
        ("event: chunk\r\ndata: {}\r\n\r\n", vec![ev("chunk", "{}")]),
        ("event: chunk\rdata: {}\r\r", vec![ev("chunk", "{}")]),
        ("data: a\ndata: b\n\n", vec![ev("message", "a\nb")]),
        ("data:a\n\n", vec![ev("message", "a")]),
        ("data:  a\n\n", vec![ev("message", " a")]),
        ("data\n\n", vec![ev("message", "")]),
        (": c\ndata: x\n\n", vec![ev("message", "x")]),
        ("event:\ndata: x\n\n", vec![ev("message", "x")]),
        ("event: e\n\n", vec![]),
        ("id: 1\nretry: 5\nfoo: bar\ndata: x\n\n", vec![ev("message", "x")]),
        ("data: unfinished", vec![]),
        ("data: x\r", vec![]),
        ("data: x\r\r", vec![ev("message", "x")]),
        ("\u{feff}data: x\n\n", vec![ev("message", "x")]),
        ("data: x\n\n\u{feff}data: y\n\n", vec![ev("message", "x")]),
        ("event: a\ndata: 1\n\nevent: b\ndata: 2\n\n", vec![ev("a", "1"), ev("b", "2")]),
    ];
    for (input, want) in cases {
        assert_eq!(&parse_all(input.as_bytes()), want, "{input:?}");
    }
    let mut p = Parser::new();
    let mut got = p.feed(b"data: x\r");
    got.extend(p.feed(b"\n\r\n"));
    assert_eq!(got, vec![ev("message", "x")], "CR then LF across feeds is one line end");
    let mut p = Parser::new();
    let mut got = p.feed(b"\xef");
    got.extend(p.feed(b"\xbb"));
    got.extend(p.feed(b"\xbfdata: y\n\n"));
    assert_eq!(got, vec![ev("message", "y")]);
}

#[test]
fn parser_splits_are_equivalent() {
    let tokens: &[&[u8]] = &[
        b"event: chunk",
        b"event: tw-end",
        b"data: ",
        b"data:",
        b"{\"a\":1}",
        b":",
        b" ",
        b"\n",
        b"\r",
        b"\r\n",
        b"\xef\xbb\xbf",
        b"x",
        b"id: 3",
        "é".as_bytes(),
        b"\x00",
        b"\xff",
    ];
    let mut state = 1u64;
    let mut rnd = |n: usize| {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((state >> 33) as usize) % n
    };
    for _ in 0..3000 {
        let mut input = Vec::new();
        for _ in 0..rnd(30) {
            input.extend_from_slice(tokens[rnd(tokens.len())]);
        }
        let want = parse_all(&input);
        let mut p = Parser::new();
        let mut got = Vec::new();
        let mut rest = &input[..];
        while !rest.is_empty() {
            let cut = 1 + rnd(rest.len());
            got.extend(p.feed(&rest[..cut]));
            rest = &rest[cut..];
        }
        got.extend(p.finish());
        assert_eq!(got, want, "{input:?}");
    }
}

#[test]
fn parser_is_linear_on_a_long_line() {
    let line = vec![b'x'; 4 << 20];
    for step in [1usize, 7] {
        let mut p = Parser::new();
        let start = Instant::now();
        p.feed(b"data: ");
        for piece in line.chunks(step) {
            p.feed(piece);
        }
        let got = p.feed(b"\n\n");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{step}-byte pieces: {:?}",
            start.elapsed()
        );
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data.len(), line.len());
    }
}

#[test]
fn chunks() {
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    for ok in
        [r#"{"a":1}"#, "[1,2]", " {\"a\":\"\\n\"}\n", r#"{"s":"[[[["}"#, "[1e400]", r#"["\ud800"]"#]
    {
        assert_eq!(decode_chunk(ok.as_bytes()), Ok(()), "{ok}");
    }
    assert_eq!(decode_chunk(deep(MAX_CHUNK_DEPTH).as_bytes()), Ok(()));
    for bad in [
        "1",
        "\"s\"",
        "null",
        "true",
        "{",
        "NaN",
        "[NaN]",
        "[Infinity]",
        "{\"a\":1}x",
        "",
        "\u{feff}{}",
    ] {
        assert!(decode_chunk(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(decode_chunk(b"[\"\xff\"]").is_err());
    assert!(decode_chunk(deep(MAX_CHUNK_DEPTH + 1).as_bytes()).is_err());
    assert!(decode_chunk(deep(100_000).as_bytes()).is_err(), "no stack overflow");
    assert!(encode_chunk(b" [3]").is_ok());
    for bad in [&b"{\"a\":\n1}"[..], b"\"s\"", b"{\"a\"", b"\t\n{}"] {
        assert!(encode_chunk(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn trailers() {
    let d = "ab".repeat(32);
    let good = format!(r#"{{"digest":"{d}","count":3,"signature":"0x00"}}"#);
    let t = parse_trailer(good.as_bytes()).unwrap();
    assert_eq!(t, Trailer { digest: d.clone(), count: 3, signature: Some("0x00".into()) });
    assert_eq!(encode_trailer(&t), good.as_bytes());
    let unsigned = parse_trailer(format!(r#"{{"count":0,"digest":"{d}"}}"#).as_bytes()).unwrap();
    assert_eq!(unsigned.signature, None);
    let max =
        parse_trailer(format!(r#"{{"digest":"{d}","count":18446744073709551615}}"#).as_bytes());
    assert_eq!(max.unwrap().count, u64::MAX);
    for bad in [
        String::new(),
        "[]".into(),
        "{}".into(),
        format!(r#"{{"digest":"{d}"}}"#),
        r#"{"count":1}"#.into(),
        format!(r#"{{"digest":"{}","count":1}}"#, d.to_uppercase()),
        r#"{"digest":"ab","count":1}"#.into(),
        format!(r#"{{"digest":"{d}","count":1.0}}"#),
        format!(r#"{{"digest":"{d}","count":1e2}}"#),
        format!(r#"{{"digest":"{d}","count":-1}}"#),
        format!(r#"{{"digest":"{d}","count":-0}}"#),
        format!(r#"{{"digest":"{d}","count":true}}"#),
        format!(r#"{{"digest":"{d}","count":"1"}}"#),
        format!(r#"{{"digest":"{d}","count":18446744073709551616}}"#),
        format!(r#"{{"digest":"{d}","count":1,"signature":1}}"#),
        format!(r#"{{"digest":"{d}","count":1,"x":1}}"#),
        format!(r#"{{"digest":"{d}","count":1,"count":1}}"#),
        format!(r#"{{"digest":"{d}","d\u0069gest":"{d}","count":1}}"#),
        format!(r#"{{"digest":"{d}","count":1}}x"#),
        r#"{"digest":{},"count":1}"#.into(),
    ] {
        assert!(parse_trailer(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(parse_trailer(b"\xff").is_err());
}

#[test]
fn framing_limits_and_slots() {
    assert_eq!(encode_event("chunk", b"{}").unwrap(), b"event: chunk\ndata: {}\n\n");
    assert!(encode_event("a\nb", b"").is_err());
    assert!(encode_event("a", b"\r").is_err());
    assert_eq!(TRAILER_RESERVE, 273, "the Python reference's value");
    let s = Duration::from_secs;
    assert_eq!(StreamLimits::new(s(60), 4 << 20, s(10)).unwrap(), StreamLimits::default());
    for (d, b, i) in [
        (0, 1024, 1),
        (601, 1024, 1),
        (1, 1023, 1),
        (1, (64 << 20) + 1, 1),
        (1, 1024, 0),
        (1, 1024, 121),
    ] {
        assert!(StreamLimits::new(s(d), b, s(i)).is_err());
    }
    assert!(StreamSlots::new(0).is_err() && StreamSlots::new(257).is_err());
    let slots = Arc::new(StreamSlots::new(2).unwrap());
    let a1 = slots.acquire("a").unwrap();
    let a2 = slots.acquire("a").unwrap();
    let e = slots.acquire("a").unwrap_err();
    assert_eq!((e.code, e.status), (codes::RATE_LIMITED, 429));
    drop(slots.acquire("b").unwrap());
    drop(a1);
    assert_eq!(slots.open("a"), 1);
    drop(a2);
    assert_eq!(slots.open("a"), 0);
    let mut digest = StreamDigest::new();
    digest.update(b"{}");
    assert_eq!(digest.count(), 1);
    assert_eq!(digest.hex(), digest.hex(), "hex keeps the running hash");
}

// ---------------------------------------------------------------- miner + client

type Items = Vec<Result<Vec<u8>, BoxError>>;

fn items(v: &[&str]) -> Items {
    v.iter().map(|s| Ok(s.as_bytes().to_vec())).collect()
}

#[derive(Clone, Default)]
struct Aborts(Arc<Mutex<Vec<String>>>);

impl Aborts {
    async fn wait(&self) -> Vec<String> {
        for _ in 0..300 {
            if !self.0.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.0.lock().unwrap().clone()
    }
}

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { ::axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

type Source = Box<dyn Fn() -> stream::BoxStream<'static, Result<Vec<u8>, BoxError>> + Send + Sync>;

async fn stream_miner(key: Keypair, cfg: StreamConfig, source: Source) -> String {
    let store = Arc::new(MemoryStore::new(Duration::from_secs(60)));
    let auth = Arc::new(
        MinerAuth::new(Verifier::new(Config::new(key.ss58(), store)).unwrap())
            .with_response_key(key),
    );
    let source = Arc::new(source);
    let app = Router::new()
        .fallback(move |Extension(ctx): Extension<StreamContext>| {
            let (cfg, source) = (cfg.clone(), Arc::clone(&source));
            async move { stream_response(&ctx, &cfg, source()).await }
        })
        .layer(::axum::middleware::from_fn_with_state(auth, protect));
    serve(app).await
}

fn fixed(v: &'static [&'static str]) -> Source {
    Box::new(move || Box::pin(stream::iter(items(v))))
}

fn client(key: Keypair) -> Client {
    Client::new(Signer::new(key), reqwest::Client::new())
}

async fn open(
    c: &Client,
    url: &str,
    limits: StreamLimits,
    budget: Duration,
) -> Result<taowire_btauth::client::Stream, Error> {
    c.stream(reqwest::Method::POST, url, b"{}".to_vec(), bob().ss58(), limits, budget).await
}

#[tokio::test]
async fn round_trip_sr25519_and_ed25519() {
    let ed_bob = Keypair::ed25519_from_seed(&seed(BOB_SEED));
    for key in [bob(), ed_bob] {
        let ss58 = key.ss58().to_owned();
        let url = stream_miner(
            key,
            StreamConfig::default(),
            fixed(&[r#"{"t":"Hel"}"#, r#"{"t":"lo ☃"}"#, "[1]"]),
        )
        .await;
        let s = client(alice())
            .stream(
                reqwest::Method::POST,
                &format!("{url}/v1/s?x=1"),
                vec![],
                &ss58,
                StreamLimits::default(),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        let chunks = s.finish().await.unwrap();
        assert_eq!(
            chunks,
            vec![
                br#"{"t":"Hel"}"#.to_vec(),
                r#"{"t":"lo ☃"}"#.as_bytes().to_vec(),
                b"[1]".to_vec()
            ]
        );
    }
    let url = stream_miner(bob(), StreamConfig::default(), fixed(&[])).await;
    let mut s =
        open(&client(alice()), &format!("{url}/"), StreamLimits::default(), Duration::from_secs(5))
            .await
            .unwrap();
    assert_eq!(s.next().await.unwrap(), None, "zero chunks is a valid stream");
}

#[tokio::test]
async fn errors_before_the_first_byte() {
    let cfg =
        StreamConfig { first_chunk_timeout: Duration::from_millis(100), ..StreamConfig::default() };
    let cases: Vec<(Source, &str)> = vec![
        (
            Box::new(|| Box::pin(stream::iter(vec![Err::<Vec<u8>, BoxError>("boom".into())]))),
            codes::HANDLER_ERROR,
        ),
        (
            Box::new(|| {
                Box::pin(stream::iter(vec![Err::<Vec<u8>, BoxError>(Box::new(Error::new(
                    "tw.forbidden_not_validator",
                    "",
                )))]))
            }),
            "tw.forbidden_not_validator",
        ),
        (Box::new(|| Box::pin(stream::pending())), codes::HANDLER_TIMEOUT),
    ];
    for (source, code) in cases {
        let url = stream_miner(bob(), cfg.clone(), source).await;
        let e = open(
            &client(alice()),
            &format!("{url}/"),
            StreamLimits::default(),
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, code);
    }
}

fn after_first(
    rest: stream::BoxStream<'static, Result<Vec<u8>, BoxError>>,
) -> stream::BoxStream<'static, Result<Vec<u8>, BoxError>> {
    Box::pin(stream::iter(items(&["[1]"])).chain(rest))
}

use futures_util::StreamExt as _;

#[tokio::test]
async fn miner_aborts_end_without_trailer() {
    let s = Duration::from_secs;
    let big: &'static str = Box::leak(format!(r#"{{"x":"{}"}}"#, "a".repeat(900)).into_boxed_str());
    let big_items: &'static [&'static str] = Box::leak(vec![big].into_boxed_slice());
    let cases: Vec<(&str, StreamLimits, Source)> = vec![
        (
            "handler_error",
            StreamLimits::default(),
            Box::new(|| {
                after_first(Box::pin(stream::iter(vec![Err::<Vec<u8>, BoxError>("boom".into())])))
            }),
        ),
        ("bad_chunk", StreamLimits::default(), fixed(&["[1]", "5"])),
        ("bad_chunk", StreamLimits::default(), fixed(&["[1]", "{\"a\":\n1}"])),
        (
            "bad_chunk",
            StreamLimits::default(),
            Box::new(|| {
                Box::pin(stream::iter(vec![Ok::<_, BoxError>(
                    format!("{}{}", "[".repeat(129), "]".repeat(129)).into_bytes(),
                )]))
            }),
        ),
        (
            "idle_timeout",
            StreamLimits::new(s(60), 4 << 20, s(1)).unwrap(),
            Box::new(|| after_first(Box::pin(stream::pending()))),
        ),
        ("max_bytes", StreamLimits::new(s(60), 1024, s(10)).unwrap(), fixed(big_items)),
        (
            "max_duration",
            StreamLimits::new(s(1), 4 << 20, s(10)).unwrap(),
            Box::new(|| {
                Box::pin(stream::unfold((), |()| async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Some((Ok::<_, BoxError>(b"[1]".to_vec()), ()))
                }))
            }),
        ),
    ];
    for (reason, limits, source) in cases {
        let aborts = Aborts::default();
        let sink = aborts.clone();
        let slots = Arc::new(StreamSlots::new(1).unwrap());
        let cfg = StreamConfig {
            limits,
            slots: Arc::clone(&slots),
            route: "/v1/s".into(),
            on_abort: Some(Arc::new(move |_route: &str, r: &str| {
                sink.0.lock().unwrap().push(r.to_owned())
            })),
            ..StreamConfig::default()
        };
        let url = stream_miner(bob(), cfg, source).await;
        let st = open(&client(alice()), &format!("{url}/"), StreamLimits::default(), s(30))
            .await
            .unwrap();
        let e = st.finish().await.unwrap_err();
        assert_eq!(e.code, codes::BAD_RESPONSE_SIGNATURE, "{reason}");
        assert_eq!(aborts.wait().await, vec![reason.to_owned()]);
        for _ in 0..200 {
            if slots.open(alice().ss58()) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(slots.open(alice().ss58()), 0, "{reason}: slot released");
    }
}

#[test]
fn default_configs_share_the_process_slots() {
    let (a, b) = (StreamConfig::default(), StreamConfig::default());
    assert!(Arc::ptr_eq(&a.slots, &b.slots), "a per-request default config must not reset D36");
}

#[tokio::test]
async fn open_streams_per_caller() {
    let slots = Arc::new(StreamSlots::new(1).unwrap());
    let cfg = StreamConfig { slots: Arc::clone(&slots), ..StreamConfig::default() };
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let g = Arc::clone(&gate);
    let source: Source = Box::new(move || {
        let g = Arc::clone(&g);
        after_first(Box::pin(stream::once(async move {
            let _permit = g.acquire().await;
            Ok::<_, BoxError>(b"[2]".to_vec())
        })))
    });
    let url = stream_miner(bob(), cfg, source).await;
    let budget = Duration::from_secs(10);
    let mut first =
        open(&client(alice()), &format!("{url}/"), StreamLimits::default(), budget).await.unwrap();
    assert!(first.next().await.unwrap().is_some());
    let e = open(&client(alice()), &format!("{url}/"), StreamLimits::default(), budget)
        .await
        .unwrap_err();
    assert_eq!(e.code, codes::RATE_LIMITED, "signed 429 before any byte");
    let other = open(&client(alice_ed()), &format!("{url}/"), StreamLimits::default(), budget)
        .await
        .unwrap();
    gate.add_permits(2);
    assert_eq!(first.finish().await.unwrap().len(), 2);
    assert_eq!(other.finish().await.unwrap().len(), 2);
    assert_eq!(slots.open(alice().ss58()), 0);
}

// ---------------------------------------------------------------- client against a fake miner

#[derive(Clone)]
struct Fake {
    chunks: Vec<String>,
    before: String,
    extra: String,
    trailer: Option<fn(&str, u64, &str) -> String>,
    headers: Vec<(&'static str, String)>,
    drop_headers: Vec<&'static str>,
    delay: Duration,
}

fn std_trailer(d: &str, n: u64, s: &str) -> String {
    format!(r#"{{"digest":"{d}","count":{n},"signature":"{s}"}}"#)
}

impl Default for Fake {
    fn default() -> Self {
        Self {
            chunks: [r#"{"i":0}"#, r#"{"i":1}"#, r#"{"i":2}"#].map(String::from).to_vec(),
            before: String::new(),
            extra: String::new(),
            trailer: Some(std_trailer),
            headers: vec![],
            drop_headers: vec![],
            delay: Duration::ZERO,
        }
    }
}

async fn fake_miner(f: Fake) -> String {
    let app = Router::new().fallback(move |headers: HeaderMap, _req: Request| {
        let f = f.clone();
        async move {
            let key = bob();
            let nonce: u64 = headers["x-bittensor-nonce"].to_str().unwrap().parse().unwrap();
            let sender = headers["x-bittensor-hotkey"].to_str().unwrap().to_owned();
            let mut d = StreamDigest::new();
            for c in &f.chunks {
                d.update(c.as_bytes());
            }
            let p = response_payload(Scheme::Sr25519, nonce, &sender, key.ss58(), 200, &d.hex());
            let sig = format!("0x{}", hex::encode(key.sign(&p)));
            let mut frames = vec![f.before.clone()];
            frames.extend(f.chunks.iter().map(|c| format!("event: chunk\ndata: {c}\n\n")));
            if let Some(t) = f.trailer {
                frames.push(format!("event: tw-end\ndata: {}\n\n", t(&d.hex(), d.count(), &sig)));
            }
            frames.push(f.extra.clone());
            let delay = f.delay;
            let body = stream::iter(frames).then(move |fr| async move {
                tokio::time::sleep(delay).await;
                Ok::<_, Infallible>(Bytes::from(fr))
            });
            let mut resp = Response::new(Body::from_stream(body));
            let h = resp.headers_mut();
            h.insert("content-type", "text/event-stream; charset=utf-8".parse().unwrap());
            h.insert("x-tw-resp-version", "1".parse().unwrap());
            h.insert("x-tw-resp-hotkey", key.ss58().parse().unwrap());
            for (k, v) in &f.headers {
                h.insert(*k, v.parse().unwrap());
            }
            for k in &f.drop_headers {
                h.remove(*k);
            }
            resp
        }
    });
    serve(app).await
}

async fn run_fake(f: Fake, limits: StreamLimits, budget: Duration) -> Result<Vec<Vec<u8>>, Error> {
    let url = fake_miner(f).await;
    open(&client(alice()), &format!("{url}/s"), limits, budget).await?.finish().await
}

#[tokio::test]
async fn client_rules() {
    let ok = StreamLimits::default();
    let t = Duration::from_secs(5);
    assert_eq!(run_fake(Fake::default(), ok, t).await.unwrap().len(), 3);
    let quiet =
        Fake { before: ": hi\n\nevent: ping\ndata: x\n\nid: 4\n\n".into(), ..Fake::default() };
    assert_eq!(
        run_fake(quiet, ok, t).await.unwrap().len(),
        3,
        "comments and unknown events are ignored"
    );
    assert_eq!(run_fake(Fake { chunks: vec![], ..Fake::default() }, ok, t).await.unwrap().len(), 0);
    let bad = codes::BAD_RESPONSE_SIGNATURE;
    let cases: Vec<(Fake, &str)> = vec![
        (Fake { extra: "event: chunk\ndata: {}\n\n".into(), ..Fake::default() }, bad),
        (Fake { extra: "event: other\ndata: x\n\n".into(), ..Fake::default() }, bad),
        (
            Fake {
                extra: format!("event: tw-end\ndata: {}\n\n", std_trailer("0", 0, "0x")),
                ..Fake::default()
            },
            bad,
        ),
        (Fake { trailer: None, ..Fake::default() }, bad),
        (Fake { trailer: Some(|d, n, s| std_trailer(d, n + 1, s)), ..Fake::default() }, bad),
        (
            Fake { trailer: Some(|_, n, s| std_trailer(&"0".repeat(64), n, s)), ..Fake::default() },
            bad,
        ),
        (
            Fake {
                trailer: Some(|d, n, _| std_trailer(d, n, &format!("0x{}", "00".repeat(64)))),
                ..Fake::default()
            },
            bad,
        ),
        (
            Fake {
                trailer: Some(|d, n, _| format!(r#"{{"digest":"{d}","count":{n}}}"#)),
                ..Fake::default()
            },
            bad,
        ),
        (Fake { trailer: Some(|_, _, _| r#"{"digest":1}"#.into()), ..Fake::default() }, bad),
        (Fake { drop_headers: vec!["x-tw-resp-version"], ..Fake::default() }, bad),
        (Fake { drop_headers: vec!["x-tw-resp-hotkey"], ..Fake::default() }, bad),
        (Fake { headers: vec![("x-tw-resp-signature", "0x00".into())], ..Fake::default() }, bad),
        (
            Fake { headers: vec![("x-tw-resp-hotkey", alice().ss58().into())], ..Fake::default() },
            bad,
        ),
        (
            Fake { headers: vec![("content-encoding", "gzip".into())], ..Fake::default() },
            codes::INVALID_RESPONSE,
        ),
        (
            Fake { chunks: vec!["[1]".into(), "5".into()], ..Fake::default() },
            codes::INVALID_RESPONSE,
        ),
        (Fake { chunks: vec!["{x".into()], ..Fake::default() }, codes::INVALID_RESPONSE),
    ];
    for (i, (f, code)) in cases.into_iter().enumerate() {
        assert_eq!(run_fake(f, ok, t).await.unwrap_err().code, code, "case {i}");
    }
}

#[tokio::test]
async fn client_detects_tampering_in_transit() {
    let edits: Vec<fn(String) -> String> = vec![
        |b| b.replacen(r#"{"i":1}"#, r#"{"i":7}"#, 1),
        |b| {
            b.replacen(r#"{"i":0}"#, "#", 1).replacen(r#"{"i":1}"#, r#"{"i":0}"#, 1).replacen(
                '#',
                r#"{"i":1}"#,
                1,
            )
        },
        |b| b.replacen("event: chunk\ndata: {\"i\":1}\n\n", "", 1),
        |b| b.replacen("event: tw-end", "event: chunk\ndata: {}\n\nevent: tw-end", 1),
    ];
    let miner = stream_miner(
        bob(),
        StreamConfig::default(),
        fixed(&[r#"{"i":0}"#, r#"{"i":1}"#, r#"{"i":2}"#]),
    )
    .await;
    for edit in edits {
        let upstream = miner.clone();
        let relay = Router::new().fallback(move |req: Request| {
            let upstream = upstream.clone();
            async move {
                let (parts, body) = req.into_parts();
                let body = ::axum::body::to_bytes(body, 1 << 20).await.unwrap();
                let mut out = reqwest::Client::new()
                    .request(parts.method.clone(), format!("{upstream}{}", parts.uri));
                for (k, v) in &parts.headers {
                    out = out.header(k, v);
                }
                let resp = out.body(body).send().await.unwrap();
                let headers = resp.headers().clone();
                let text = edit(resp.text().await.unwrap());
                let mut r = Response::new(Body::from(text));
                for (k, v) in &headers {
                    if k != "content-length" && k != "transfer-encoding" {
                        r.headers_mut().insert(k, v.clone());
                    }
                }
                r
            }
        });
        let url = serve(relay).await;
        let e = open(
            &client(alice()),
            &format!("{url}/"),
            StreamLimits::default(),
            Duration::from_secs(5),
        )
        .await
        .unwrap()
        .finish()
        .await
        .unwrap_err();
        assert_eq!(e.code, codes::BAD_RESPONSE_SIGNATURE);
    }
}

#[tokio::test]
async fn client_limits() {
    let s = Duration::from_secs;
    let slow = Fake { delay: Duration::from_millis(1500), ..Fake::default() };
    let e =
        run_fake(slow, StreamLimits::new(s(60), 4 << 20, s(1)).unwrap(), s(30)).await.unwrap_err();
    assert_eq!(e.code, codes::TIMEOUT, "idle");
    let drip = Fake { delay: Duration::from_millis(400), ..Fake::default() };
    let e = run_fake(drip.clone(), StreamLimits::default(), Duration::from_millis(1200))
        .await
        .unwrap_err();
    assert_eq!(e.code, codes::TIMEOUT, "deadline");
    let big =
        Fake { chunks: vec![format!(r#"{{"x":"{}"}}"#, "a".repeat(2000))], ..Fake::default() };
    let e = run_fake(big, StreamLimits::new(s(60), 1024, s(10)).unwrap(), s(5)).await.unwrap_err();
    assert_eq!(e.code, codes::RESPONSE_TOO_LARGE);
    // The caller's own time with a chunk is not idle.
    let url = fake_miner(Fake::default()).await;
    let mut st = open(
        &client(alice()),
        &format!("{url}/"),
        StreamLimits::new(s(60), 4 << 20, s(1)).unwrap(),
        s(10),
    )
    .await
    .unwrap();
    while st.next().await.unwrap().is_some() {
        tokio::time::sleep(Duration::from_millis(1300)).await;
    }
    assert_eq!(st.chunks().len(), 3);
}

#[tokio::test]
async fn client_non_stream_answers() {
    async fn answer(status: u16, body: &'static str, sign: bool) -> String {
        let app = Router::new().fallback(move |headers: HeaderMap| async move {
            let nonce: u64 = headers["x-bittensor-nonce"].to_str().unwrap().parse().unwrap();
            let sender = headers["x-bittensor-hotkey"].to_str().unwrap().to_owned();
            let mut r = Response::new(Body::from(body));
            *r.status_mut() = ::axum::http::StatusCode::from_u16(status).unwrap();
            if sign {
                for (k, v) in sign_response(&bob(), nonce, &sender, status, body.as_bytes()) {
                    r.headers_mut()
                        .insert(::axum::http::HeaderName::try_from(k).unwrap(), v.parse().unwrap());
                }
            }
            r
        });
        serve(app).await
    }
    let cases = [
        (
            403,
            r#"{"error":{"code":"tw.forbidden_not_validator","message":"x","request_id":null}}"#,
            true,
            "tw.forbidden_not_validator",
        ),
        (
            401,
            r#"{"error":{"code":"tw.auth_stale","message":"x","request_id":null}}"#,
            false,
            "tw.auth_stale",
        ),
        (502, "bad gateway", false, "tw.http_502"),
        (200, r#"{"a":1}"#, true, codes::INVALID_RESPONSE),
        (200, r#"{"a":1}"#, false, codes::BAD_RESPONSE_SIGNATURE),
    ];
    for (status, body, sign, code) in cases {
        let url = answer(status, body, sign).await;
        let e = open(
            &client(alice()),
            &format!("{url}/"),
            StreamLimits::default(),
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, code, "{status} {body}");
    }
    let e = open(
        &client(alice()),
        "http://127.0.0.1:1/",
        StreamLimits::default(),
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, codes::CONNECT_ERROR);
    let e = open(&client(alice()), "::bad", StreamLimits::default(), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(e.code, codes::CONNECT_ERROR);
}

#[tokio::test]
async fn a_slow_body_is_refused_after_the_body_timeout() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let store = Arc::new(MemoryStore::new(Duration::from_secs(60)));
    let auth = Arc::new(
        MinerAuth::new(Verifier::new(Config::new(bob().ss58(), store)).unwrap())
            .with_body_timeout(Duration::from_millis(300)),
    );
    let app = Router::new()
        .fallback(|| async { "ok" })
        .layer(::axum::middleware::from_fn_with_state(auth, protect));
    let url = serve(app).await;
    let addr = url.trim_start_matches("http://");
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{").await.unwrap();
    let started = Instant::now();
    let mut buf = vec![0u8; 512];
    let n =
        tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await.unwrap().unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");
    assert!(head.contains("tw.auth_malformed"));
    assert!(started.elapsed() < Duration::from_secs(3));
}
