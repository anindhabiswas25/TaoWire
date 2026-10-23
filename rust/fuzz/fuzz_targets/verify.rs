//! cargo fuzz target on the verify path (spec 16.5 item 3): arbitrary header
//! values, method, target and body. Verify must never panic, must only answer
//! with a 401 `tw.auth_*` code, and may accept only the genuine seed request.
#![no_main]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use tensorwire_btauth::{Config, MemoryStore, Verifier};

const BOB: &str = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
const ALICE: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
const NOW: u64 = 1_752_076_800_000_000_000;

/// The memory store's future is always ready: poll it once.
fn ready<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => unreachable!("MemoryStore never waits"),
    }
}

type Input = (String, String, String, String, Option<String>, String, String, String, Vec<u8>);

fuzz_target!(|input: Input| {
    let (version, hotkey, receiver, nonce, crypto, sig, method, target, body) = input;
    let mut cfg = Config::new(BOB, Arc::new(MemoryStore::new(Duration::from_secs(60))));
    cfg.now_ns = Some(Box::new(|| NOW));
    let verifier = Verifier::new(cfg).expect("valid config");
    let mut h = vec![
        ("X-Bittensor-Version", version.as_str()),
        ("X-Bittensor-Hotkey", hotkey.as_str()),
        ("X-Bittensor-Receiver", receiver.as_str()),
        ("X-Bittensor-Nonce", nonce.as_str()),
        ("X-Bittensor-Signature", sig.as_str()),
    ];
    if let Some(c) = crypto.as_deref() {
        h.push(("X-Bittensor-Crypto", c));
    }
    match ready(verifier.verify(h, &body, &method, &target)) {
        Err(e) => assert!(e.status == 401 && e.code.starts_with("tw.auth_"), "{e}"),
        Ok(caller) => assert!(
            caller.hotkey == ALICE
                && method.eq_ignore_ascii_case("post")
                && target == "/generate?stream=false"
                && body == br#"{"prompt": "hello"}"#,
            "accepted an unsigned request"
        ),
    }
});
