use sha2::{Digest, Sha256};

/// First line of every btauth/1 payload.
pub const PROTOCOL: &str = "btauth/1";

/// A signature scheme. An absent `X-Bittensor-Crypto` header means sr25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Schnorrkel over ristretto255, signing context `b"substrate"`.
    Sr25519,
    /// RFC 8032 ed25519.
    Ed25519,
}

impl Scheme {
    /// The name used in payloads and headers.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sr25519 => "sr25519",
            Self::Ed25519 => "ed25519",
        }
    }

    /// The scheme for an exact header value (`"sr25519"` or `"ed25519"`).
    pub fn from_header(value: &str) -> Option<Self> {
        match value {
            "sr25519" => Some(Self::Sr25519),
            "ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// Lowercase hex sha256 of the raw body bytes.
pub fn body_sha256(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// The btauth/1 signed payload (spec 4.2): eight lines joined by `\n`, no
/// trailing newline. `target` is the request target exactly as sent
/// (percent-encoded path plus `?query`); `None` receiver writes `-`.
pub fn build_payload(
    scheme: Scheme,
    method: &str,
    target: &str,
    body: &[u8],
    nonce_ns: u64,
    sender: &str,
    receiver: Option<&str>,
) -> Vec<u8> {
    [
        PROTOCOL,
        scheme.as_str(),
        &method.to_uppercase(),
        target,
        &body_sha256(body),
        &nonce_ns.to_string(),
        sender,
        receiver.unwrap_or("-"),
    ]
    .join("\n")
    .into_bytes()
}
