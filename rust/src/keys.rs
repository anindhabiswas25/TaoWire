use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use schnorrkel::{ExpansionMode, MiniSecretKey};

use crate::nonce::NonceSource;
use crate::payload::{build_payload, Scheme};
use crate::ss58::encode_ss58;

/// The substrate signing context for sr25519 (spec 4.2).
const SIGNING_CONTEXT: &[u8] = b"substrate";

enum Secret {
    Sr25519(schnorrkel::Keypair),
    Ed25519(SigningKey),
}

/// A hotkey that can sign: sr25519 or ed25519. `Debug` never shows secrets.
pub struct Keypair {
    secret: Secret,
    public: [u8; 32],
    ss58: String,
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keypair({}, {})", self.ss58, self.scheme().as_str())
    }
}

impl Keypair {
    /// An sr25519 hotkey from its 32-byte mini secret (a Bittensor hotkey
    /// file's `secretSeed`), expanded the substrate way.
    pub fn sr25519_from_seed(seed: &[u8; 32]) -> Self {
        let mini = MiniSecretKey::from_bytes(seed).expect("32 bytes is a mini secret");
        let kp = mini.expand_to_keypair(ExpansionMode::Ed25519);
        let public = kp.public.to_bytes();
        Self { secret: Secret::Sr25519(kp), public, ss58: encode_ss58(&public) }
    }

    /// An ed25519 hotkey from its 32-byte RFC 8032 seed.
    pub fn ed25519_from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        let public = key.verifying_key().to_bytes();
        Self { secret: Secret::Ed25519(key), public, ss58: encode_ss58(&public) }
    }

    /// The key's scheme.
    pub fn scheme(&self) -> Scheme {
        match self.secret {
            Secret::Sr25519(_) => Scheme::Sr25519,
            Secret::Ed25519(_) => Scheme::Ed25519,
        }
    }

    /// The raw public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The prefix-42 SS58 address.
    pub fn ss58(&self) -> &str {
        &self.ss58
    }

    /// Sign exactly `msg`, never a wrapped form. ed25519 is deterministic,
    /// sr25519 randomized.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        match &self.secret {
            Secret::Sr25519(kp) => kp.sign_simple(SIGNING_CONTEXT, msg).to_bytes(),
            Secret::Ed25519(key) => key.sign(msg).to_bytes(),
        }
    }
}

/// Whether a public key has a signature that verifies for every message: the
/// sr25519 (ristretto) identity, or an ed25519 point of small order. Verifiers
/// refuse such keys (`negative.json` N63, N64).
pub fn is_weak_public_key(scheme: Scheme, public_key: &[u8; 32]) -> bool {
    match scheme {
        Scheme::Sr25519 => public_key == &[0u8; 32],
        Scheme::Ed25519 => VerifyingKey::from_bytes(public_key).is_ok_and(|vk| vk.is_weak()),
    }
}

/// Verify `sig` over exactly `msg` under `scheme` only. Undecodable keys or
/// signatures (a missing schnorrkel marker, a non-canonical S) are invalid.
pub(crate) fn verify_signature(
    scheme: Scheme,
    public_key: &[u8; 32],
    msg: &[u8],
    sig: &[u8; 64],
) -> bool {
    if is_weak_public_key(scheme, public_key) {
        return false;
    }
    match scheme {
        Scheme::Sr25519 => {
            let (Ok(pk), Ok(s)) = (
                schnorrkel::PublicKey::from_bytes(public_key),
                schnorrkel::Signature::from_bytes(sig),
            ) else {
                return false;
            };
            pk.verify_simple(SIGNING_CONTEXT, msg, &s).is_ok()
        }
        Scheme::Ed25519 => VerifyingKey::from_bytes(public_key)
            .is_ok_and(|vk| vk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()),
    }
}

/// Signs outgoing requests (the validator side) with fresh nonces.
#[derive(Debug)]
pub struct Signer {
    key: Keypair,
    nonce: NonceSource,
}

impl Signer {
    /// A signer for `key` with its own strictly increasing nonces.
    pub fn new(key: Keypair) -> Self {
        Self { key, nonce: NonceSource::new() }
    }

    /// A signer whose nonces come from `nonce` (tests).
    pub fn with_nonce_source(key: Keypair, nonce: NonceSource) -> Self {
        Self { key, nonce }
    }

    /// The signing key.
    pub fn key(&self) -> &Keypair {
        &self.key
    }

    /// The btauth/1 headers for one request and the nonce used. `target` is
    /// the request target exactly as sent. Sign again for every retry.
    pub fn sign(
        &self,
        method: &str,
        target: &str,
        body: &[u8],
        receiver: Option<&str>,
    ) -> (Vec<(String, String)>, u64) {
        let nonce = self.nonce.next();
        let k = &self.key;
        let payload = build_payload(k.scheme(), method, target, body, nonce, k.ss58(), receiver);
        let sig = k.sign(&payload);
        let mut h = vec![
            ("X-Bittensor-Version".to_owned(), "1".to_owned()),
            ("X-Bittensor-Hotkey".to_owned(), k.ss58().to_owned()),
        ];
        if let Some(r) = receiver {
            h.push(("X-Bittensor-Receiver".to_owned(), r.to_owned()));
        }
        h.push(("X-Bittensor-Nonce".to_owned(), nonce.to_string()));
        if k.scheme() == Scheme::Ed25519 {
            h.push(("X-Bittensor-Crypto".to_owned(), "ed25519".to_owned()));
        }
        h.push(("X-Bittensor-Signature".to_owned(), format!("0x{}", hex::encode(sig))));
        (h, nonce)
    }
}
