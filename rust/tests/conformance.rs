//! The shared conformance vectors (spec 11.7), `cargo test --test conformance`.
//! Every file except `legacy_v10.json` (Python only). `python_reference`
//! notes are ignored: Rust gives the normative answer in `expected`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use tensorwire_btauth::*;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../conformance/vectors")
}

fn load(name: &str) -> Value {
    let text = std::fs::read_to_string(dir().join(name)).expect("vector file");
    let v: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(v["schema_version"], 1, "{name}");
    assert!(!v["vectors"].as_array().expect("vectors").is_empty(), "{name}");
    v
}

#[derive(Deserialize, Clone)]
struct DevKey {
    scheme: String,
    secret_seed_hex: String,
    public_key_hex: String,
    ss58: String,
}

fn dev_keys() -> HashMap<String, DevKey> {
    serde_json::from_value(load("payload.json")["keys"].clone()).expect("keys")
}

fn keypair(k: &DevKey) -> Keypair {
    let seed: [u8; 32] = hex::decode(&k.secret_seed_hex).unwrap().try_into().unwrap();
    match k.scheme.as_str() {
        "ed25519" => Keypair::ed25519_from_seed(&seed),
        _ => Keypair::sr25519_from_seed(&seed),
    }
}

fn key_by_ss58(ss58: &str) -> Keypair {
    keypair(dev_keys().values().find(|k| k.ss58 == ss58).expect("dev key"))
}

fn b64(s: &str) -> Vec<u8> {
    // Small standard-alphabet decoder (no extra dependency for tests).
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|c| *c != b'=') {
        acc = (acc << 6) | A.iter().position(|a| *a == c).expect("base64") as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn u64_of(v: &Value) -> u64 {
    v.as_str().expect("string number").parse().expect("u64")
}

fn pairs(v: &Value) -> Vec<(String, String)> {
    match v {
        Value::Array(a) => a
            .iter()
            .map(|p| (p[0].as_str().unwrap().to_owned(), p[1].as_str().unwrap().to_owned()))
            .collect(),
        Value::Object(m) => {
            m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned())).collect()
        }
        _ => panic!("headers"),
    }
}

fn borrowed(p: &[(String, String)]) -> Vec<(&str, &str)> {
    p.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

#[test]
fn conformance_payload() {
    for v in load("payload.json")["vectors"].as_array().unwrap() {
        let i = &v["inputs"];
        let body = b64(i["body_base64"].as_str().unwrap());
        assert_eq!(body_sha256(&body), v["expected"]["body_sha256"], "{}", v["id"]);
        let scheme = Scheme::from_header(i["scheme"].as_str().unwrap()).unwrap();
        let got = build_payload(
            scheme,
            i["method"].as_str().unwrap(),
            i["target"].as_str().unwrap(),
            &body,
            u64_of(&i["nonce"]),
            i["sender_ss58"].as_str().unwrap(),
            i["receiver_ss58"].as_str(),
        );
        assert_eq!(got, b64(v["expected"]["payload_base64"].as_str().unwrap()), "{}", v["id"]);
    }
}

#[test]
fn conformance_keys() {
    for (name, k) in dev_keys() {
        let kp = keypair(&k);
        assert_eq!(hex::encode(kp.public_key()), k.public_key_hex, "{name}");
        assert_eq!(kp.ss58(), k.ss58, "{name}");
        assert_eq!(decode_ss58(&k.ss58), Some(kp.public_key()), "{name}");
    }
}

async fn run_verify(v: &Value) -> Result<Caller, Error> {
    let i = &v["inputs"];
    let now = u64_of(&i["now_ns"]);
    let mut cfg = Config::new(
        i["self_hotkey"].as_str().unwrap(),
        Arc::new(MemoryStore::new(Duration::from_secs(60))),
    );
    cfg.max_age = Duration::from_secs(i["max_age_s"].as_u64().unwrap());
    cfg.allowed_skew = Duration::from_secs(i["allowed_skew_s"].as_u64().unwrap());
    cfg.now_ns = Some(Box::new(move || now));
    let verifier = Verifier::new(cfg).unwrap();
    let call = |r: &Value| {
        let h = pairs(&r["headers"]);
        let body = b64(r["body_base64"].as_str().unwrap());
        let method = r["method"].as_str().unwrap().to_owned();
        let target = r["target"].as_str().unwrap().to_owned();
        (h, body, method, target)
    };
    if !i["prior"].is_null() {
        let (h, body, m, t) = call(&i["prior"]);
        verifier.verify(borrowed(&h), &body, &m, &t).await.expect("prior accepted");
    }
    let (h, body, m, t) = call(i);
    verifier.verify(borrowed(&h), &body, &m, &t).await
}

async fn check_verify_file(name: &str) {
    for v in load(name)["vectors"].as_array().unwrap() {
        let e = &v["expected"];
        match run_verify(v).await {
            Ok(caller) => {
                assert!(e["valid"].as_bool().unwrap(), "{} accepted, want {}", v["id"], e["code"]);
                assert_eq!(caller.hotkey, e["caller_ss58"].as_str().unwrap(), "{}", v["id"]);
            }
            Err(err) => {
                assert!(!e["valid"].as_bool().unwrap(), "{} refused: {err}", v["id"]);
                assert_eq!(err.code, e["code"].as_str().unwrap(), "{} ({err})", v["id"]);
                assert_eq!(u64::from(err.status), e["status"].as_u64().unwrap(), "{}", v["id"]);
            }
        }
    }
}

#[tokio::test]
async fn conformance_negative() {
    check_verify_file("negative.json").await;
}

#[tokio::test]
async fn conformance_sr25519_verify() {
    check_verify_file("sr25519_verify.json").await;
}

#[tokio::test]
async fn conformance_ed25519() {
    check_verify_file("ed25519.json").await;
    let keys = dev_keys();
    for v in load("ed25519.json")["vectors"].as_array().unwrap() {
        let kp = keypair(&keys[v["inputs"]["key"].as_str().unwrap()]);
        let sig = kp.sign(v["inputs"]["signed_payload_utf8"].as_str().unwrap().as_bytes());
        assert_eq!(format!("0x{}", hex::encode(sig)), v["expected"]["signature"], "{}", v["id"]);
    }
}

#[tokio::test]
async fn conformance_sr25519_sign_then_verify() {
    for v in load("sr25519_verify.json")["vectors"].as_array().unwrap() {
        let kp = key_by_ss58(v["expected"]["caller_ss58"].as_str().unwrap());
        let payload = v["inputs"]["signed_payload_utf8"].as_str().unwrap().as_bytes();
        let sig = kp.sign(payload);
        // Through the public verify path: rebuild the vector's request with our signature.
        let mut h = pairs(&v["inputs"]["headers"]);
        for (k, val) in &mut h {
            if k.eq_ignore_ascii_case("x-bittensor-signature") {
                *val = format!("0x{}", hex::encode(sig));
            }
        }
        let mut copy = v.clone();
        copy["inputs"]["headers"] = Value::Array(
            h.into_iter().map(|(k, val)| Value::Array(vec![k.into(), val.into()])).collect(),
        );
        run_verify(&copy).await.unwrap_or_else(|e| panic!("{}: {e}", v["id"]));
    }
}

#[test]
fn conformance_twresp() {
    for v in load("twresp.json")["vectors"].as_array().unwrap() {
        let (i, e, id) = (&v["inputs"], &v["expected"], &v["id"]);
        let nonce = u64_of(&i["request_nonce"]);
        let sender = i["sender_ss58"].as_str().unwrap();
        match v["kind"].as_str().unwrap() {
            "verify" => {
                let h = pairs(&i["headers"]);
                let got = verify_response(
                    borrowed(&h),
                    i["expected_responder"].as_str().unwrap(),
                    nonce,
                    sender,
                    i["status"].as_u64().unwrap() as u16,
                    &b64(i["body_base64"].as_str().unwrap()),
                );
                assert_eq!(got.is_ok(), e["valid"].as_bool().unwrap(), "{id}: {got:?}");
                if let Err(err) = got {
                    assert_eq!(err.code, e["error_code"].as_str().unwrap(), "{id}");
                }
            }
            "stream_ed25519" => {
                let mut d = tensorwire_btauth::sse::StreamDigest::new();
                for c in i["chunks_base64"].as_array().unwrap() {
                    let data = b64(c.as_str().unwrap());
                    tensorwire_btauth::sse::decode_chunk(&data).expect("chunk");
                    d.update(&data);
                }
                let digest = d.hex();
                assert_eq!(digest, e["digest"], "{id}");
                assert_eq!(d.count(), e["count"].as_u64().unwrap(), "{id}");
                let t = tensorwire_btauth::sse::Trailer {
                    digest: digest.clone(),
                    count: d.count(),
                    signature: e["signature"].as_str().map(str::to_owned),
                };
                let encoded = tensorwire_btauth::sse::encode_trailer(&t);
                assert_eq!(tensorwire_btauth::sse::parse_trailer(&encoded).unwrap(), t, "{id}");
                let responder = i["responder_ss58"].as_str().unwrap();
                let p = response_payload(Scheme::Ed25519, nonce, sender, responder, 200, &digest);
                assert_eq!(p, e["payload_utf8"].as_str().unwrap().as_bytes(), "{id}");
                let h = [
                    ("X-TW-Resp-Version", "1"),
                    ("X-TW-Resp-Hotkey", responder),
                    ("X-TW-Resp-Crypto", "ed25519"),
                    ("X-TW-Resp-Signature", e["signature"].as_str().unwrap()),
                ];
                verify_response_digest(h, responder, nonce, sender, 200, &digest).expect("stream");
            }
            kind => {
                let body = b64(i["body_base64"].as_str().unwrap());
                let responder = i["responder_ss58"].as_str().unwrap();
                let status = i["status"].as_u64().unwrap() as u16;
                let scheme = Scheme::from_header(i["scheme"].as_str().unwrap()).unwrap();
                let p =
                    response_payload(scheme, nonce, sender, responder, status, &body_sha256(&body));
                assert_eq!(p, e["payload_utf8"].as_str().unwrap().as_bytes(), "{id}");
                let h = pairs(&e["headers"]);
                verify_response(borrowed(&h), responder, nonce, sender, status, &body)
                    .unwrap_or_else(|err| panic!("{id}: {err}"));
                if kind == "sign_ed25519" {
                    let mut ours =
                        sign_response(&key_by_ss58(responder), nonce, sender, status, &body);
                    let mut want = h.clone();
                    ours.sort();
                    want.sort();
                    assert_eq!(ours, want, "{id}");
                }
            }
        }
    }
}
