use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::error::{codes, Error};
use crate::keys::verify_signature;
use crate::nonce::wall_clock_ns;
use crate::payload::{build_payload, Scheme};
use crate::ss58::decode_ss58;
use crate::store::NonceStore;

/// Request header names (spec 4.1).
pub mod headers {
    /// `X-Bittensor-Version`.
    pub const VERSION: &str = "x-bittensor-version";
    /// `X-Bittensor-Hotkey`.
    pub const HOTKEY: &str = "x-bittensor-hotkey";
    /// `X-Bittensor-Receiver`.
    pub const RECEIVER: &str = "x-bittensor-receiver";
    /// `X-Bittensor-Nonce`.
    pub const NONCE: &str = "x-bittensor-nonce";
    /// `X-Bittensor-Crypto`.
    pub const CRYPTO: &str = "x-bittensor-crypto";
    /// `X-Bittensor-Signature`.
    pub const SIGNATURE: &str = "x-bittensor-signature";
}

/// Default freshness window (spec 4.3).
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(10);
/// Default forward clock drift (spec 4.3).
pub const DEFAULT_ALLOWED_SKEW: Duration = Duration::from_secs(2);

/// The verified sender of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// Canonical prefix-42 SS58 address.
    pub hotkey: String,
    /// Unix time in nanoseconds, from `X-Bittensor-Nonce`.
    pub nonce: u64,
    /// The scheme the request was signed with.
    pub scheme: Scheme,
}

/// Verifier settings.
pub struct Config {
    /// This server's hotkey; requests must be addressed to it.
    pub self_hotkey: String,
    /// Replay store; its retention must be at least `max_age + allowed_skew`.
    pub store: Arc<dyn NonceStore>,
    /// Freshness window (default 10 s).
    pub max_age: Duration,
    /// Forward clock drift (default 2 s).
    pub allowed_skew: Duration,
    /// Replaces the wall clock (tests).
    pub now_ns: Option<Box<dyn Fn() -> u64 + Send + Sync>>,
}

impl Config {
    /// Defaults for `self_hotkey` and `store`.
    pub fn new(self_hotkey: impl Into<String>, store: Arc<dyn NonceStore>) -> Self {
        Self {
            self_hotkey: self_hotkey.into(),
            store,
            max_age: DEFAULT_MAX_AGE,
            allowed_skew: DEFAULT_ALLOWED_SKEW,
            now_ns: None,
        }
    }
}

/// Checks btauth/1 requests addressed to one hotkey.
pub struct Verifier {
    self_hotkey: String,
    store: Arc<dyn NonceStore>,
    max_age: u64,
    allowed_skew: u64,
    now_ns: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Verifier({})", self.self_hotkey)
    }
}

fn malformed(detail: &str) -> Error {
    Error::new(codes::MALFORMED, detail)
}

fn is_hex_pairs(s: &str) -> bool {
    s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Verifier {
    /// Validates `cfg`: a prefix-42 hotkey, a positive window, and a store
    /// that remembers at least the whole window (spec 11.2 rule 10).
    pub fn new(cfg: Config) -> Result<Self, String> {
        if decode_ss58(&cfg.self_hotkey).is_none() {
            return Err("self_hotkey is not a prefix-42 SS58 address".into());
        }
        if cfg.max_age.is_zero() || cfg.allowed_skew.is_zero() {
            return Err("max_age and allowed_skew must be positive".into());
        }
        if cfg.store.retention() < cfg.max_age + cfg.allowed_skew {
            return Err("nonce store retention too short".into());
        }
        let as_ns = |d: Duration| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        Ok(Self {
            self_hotkey: cfg.self_hotkey,
            store: cfg.store,
            max_age: as_ns(cfg.max_age),
            allowed_skew: as_ns(cfg.allowed_skew),
            now_ns: cfg.now_ns.unwrap_or_else(|| Box::new(wall_clock_ns)),
        })
    }

    /// The hotkey requests must be addressed to.
    pub fn self_hotkey(&self) -> &str {
        &self.self_hotkey
    }

    /// Steps 1-4 of spec 4.3 (no replay store). Header names are matched
    /// case-insensitively; values must be text.
    fn check<'h>(
        &self,
        header_pairs: impl IntoIterator<Item = (&'h str, &'h str)>,
        body: &[u8],
        method: &str,
        target: &str,
    ) -> Result<Caller, Error> {
        // 1. shape
        let mut h: HashMap<String, &str> = HashMap::new();
        for (name, value) in header_pairs {
            let key = name.to_ascii_lowercase();
            if key.starts_with("x-bittensor-") && h.contains_key(&key) {
                return Err(malformed(&format!("duplicate {name} header")));
            }
            h.insert(key, value);
        }
        if h.get(headers::VERSION) != Some(&"1") {
            return Err(malformed("missing or unsupported X-Bittensor-Version"));
        }
        let sender = match h.get(headers::HOTKEY) {
            Some(s) if !s.is_empty() => *s,
            _ => return Err(malformed("missing X-Bittensor-Hotkey")),
        };
        let sender_key = decode_ss58(sender)
            .ok_or_else(|| malformed("X-Bittensor-Hotkey is not a Bittensor address"))?;
        let nonce_text = h.get(headers::NONCE).copied().unwrap_or("");
        if nonce_text.is_empty()
            || nonce_text.len() > 20
            || !nonce_text.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(malformed("X-Bittensor-Nonce is not a decimal integer"));
        }
        // 20 digits above u64::MAX are well-formed and far in the future.
        let nonce = nonce_text.parse::<u64>().ok();
        let scheme = match h.get(headers::CRYPTO) {
            None => Scheme::Sr25519,
            Some(c) => {
                Scheme::from_header(c).ok_or_else(|| malformed("unsupported X-Bittensor-Crypto"))?
            }
        };
        let sig_text =
            h.get(headers::SIGNATURE).ok_or_else(|| malformed("missing X-Bittensor-Signature"))?;
        let sig_hex = sig_text.strip_prefix("0x").unwrap_or(sig_text);
        if !is_hex_pairs(sig_hex) {
            return Err(malformed("X-Bittensor-Signature is not hex"));
        }

        // 2. receiver (always required)
        let receiver = *h
            .get(headers::RECEIVER)
            .ok_or_else(|| Error::new(codes::WRONG_RECEIVER, "missing X-Bittensor-Receiver"))?;
        if receiver != self.self_hotkey {
            return Err(Error::new(
                codes::WRONG_RECEIVER,
                "signed for a different receiving hotkey",
            ));
        }

        // 3. freshness
        let now = (self.now_ns)();
        let nonce = match nonce {
            Some(n) if n > now && n - now > self.allowed_skew => None,
            Some(n) if n <= now && now - n > self.max_age => {
                return Err(Error::new(codes::STALE, "nonce is too old"));
            }
            other => other,
        }
        .ok_or_else(|| Error::new(codes::STALE, "nonce is in the future"))?;

        // 4. signature, under the declared scheme only
        let sig: [u8; 64] = hex::decode(sig_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| malformed("signature is not 64 bytes"))?;
        let payload = build_payload(scheme, method, target, body, nonce, sender, Some(receiver));
        if !verify_signature(scheme, &sender_key, &payload, &sig) {
            return Err(Error::new(
                codes::BAD_SIGNATURE,
                "signature does not verify against the claimed hotkey",
            ));
        }
        Ok(Caller { hotkey: sender.to_owned(), nonce, scheme })
    }

    /// Authenticate one request (spec 4.3): shape (`tw.auth_malformed`),
    /// receiver (`tw.auth_wrong_receiver`), freshness (`tw.auth_stale`),
    /// signature (`tw.auth_bad_signature`; a wrong-length signature is
    /// `tw.auth_malformed`), then replay (`tw.auth_replayed`; an unreachable
    /// store is `tw.replay_store_unavailable`). `body` is the raw received
    /// bytes and `target` the request target as received.
    pub async fn verify<'h>(
        &self,
        header_pairs: impl IntoIterator<Item = (&'h str, &'h str)>,
        body: &[u8],
        method: &str,
        target: &str,
    ) -> Result<Caller, Error> {
        let caller = self.check(header_pairs, body, method, target)?;
        match self.store.check_and_store(&caller.hotkey, caller.nonce).await {
            Ok(true) => Ok(caller),
            Ok(false) => {
                Err(Error::new(codes::REPLAYED, "nonce already accepted from this hotkey"))
            }
            Err(e) => Err(Error::new(codes::REPLAY_STORE_UNAVAILABLE, e.to_string())),
        }
    }
}
