use std::fmt;

/// The `tw.*` codes of spec Appendix A used by this crate.
pub mod codes {
    /// `MalformedAuth` (401).
    pub const MALFORMED: &str = "tw.auth_malformed";
    /// `WrongReceiver` (401).
    pub const WRONG_RECEIVER: &str = "tw.auth_wrong_receiver";
    /// `StaleRequest` (401).
    pub const STALE: &str = "tw.auth_stale";
    /// `BadSignature` (401).
    pub const BAD_SIGNATURE: &str = "tw.auth_bad_signature";
    /// `ReplayedRequest` (401).
    pub const REPLAYED: &str = "tw.auth_replayed";
    /// Body over the limit (413).
    pub const PAYLOAD_TOO_LARGE: &str = "tw.payload_too_large";
    /// Replay store unreachable (503).
    pub const REPLAY_STORE_UNAVAILABLE: &str = "tw.replay_store_unavailable";
    /// Bucket empty or too many open streams (429).
    pub const RATE_LIMITED: &str = "tw.rate_limited";
    /// Unhandled handler failure (500).
    pub const HANDLER_ERROR: &str = "tw.handler_error";
    /// Handler exceeded its timeout (504).
    pub const HANDLER_TIMEOUT: &str = "tw.handler_timeout";
    /// Generic fallback (500).
    pub const INTERNAL: &str = "tw.internal";
    /// Client side: the answer's twresp/1 signature does not check out.
    pub const BAD_RESPONSE_SIGNATURE: &str = "tw.bad_response_signature";
    /// Client side: the answer is larger than allowed.
    pub const RESPONSE_TOO_LARGE: &str = "tw.response_too_large";
    /// Client side: no answer in time.
    pub const TIMEOUT: &str = "tw.timeout";
    /// Client side: the miner could not be reached.
    pub const CONNECT_ERROR: &str = "tw.connect_error";
    /// Client side: the answer is not what the route returns (e.g. a stream
    /// chunk that is not a JSON object or array).
    pub const INVALID_RESPONSE: &str = "tw.invalid_response";
}

/// Server-side rows of Appendix A with the Python kit's fixed public messages.
const CATALOGUE: &[(&str, u16, &str)] = &[
    ("tw.internal", 500, "internal error"),
    ("tw.rate_limited", 429, "rate limit exceeded"),
    ("tw.payload_too_large", 413, "request body exceeds the size limit"),
    ("tw.auth_malformed", 401, "malformed authentication headers"),
    ("tw.auth_wrong_receiver", 401, "request was signed for a different receiver"),
    ("tw.auth_stale", 401, "request nonce is outside the freshness window"),
    ("tw.auth_bad_signature", 401, "signature does not verify"),
    ("tw.auth_replayed", 401, "request was already accepted"),
    ("tw.forbidden_denied", 403, "caller is denied"),
    ("tw.forbidden_not_registered", 403, "caller is not registered on this subnet"),
    ("tw.forbidden_not_validator", 403, "caller has no validator permit"),
    ("tw.forbidden_low_stake", 403, "caller stake is below the minimum"),
    ("tw.forbidden_blacklisted", 403, "caller is blacklisted"),
    ("tw.invalid_request", 422, "request body does not match the route model"),
    ("tw.handler_error", 500, "handler failed"),
    ("tw.metagraph_stale", 503, "metagraph snapshot is too old to admit this caller"),
    ("tw.replay_store_unavailable", 503, "replay protection store is unavailable"),
    ("tw.handler_timeout", 504, "handler timed out"),
    ("tw.legacy_auth_failed", 401, "legacy v10 authentication failed"),
    ("tw.legacy_disabled", 410, "legacy v10 requests are no longer accepted"),
];

const CLIENT_CODES: &[&str] = &[
    codes::BAD_RESPONSE_SIGNATURE,
    codes::RESPONSE_TOO_LARGE,
    codes::TIMEOUT,
    codes::CONNECT_ERROR,
    codes::INVALID_RESPONSE,
];

/// A refusal with a stable `tw.*` code. `status` is its HTTP status (0 for
/// client-side codes); `message` is the fixed public message, safe to send to
/// an unauthenticated caller; `detail` is for logs only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct Error {
    /// The `tw.*` code.
    pub code: &'static str,
    /// HTTP status (Appendix A); 0 for client-side codes.
    pub status: u16,
    /// Fixed public message.
    pub message: &'static str,
    /// More context, for logs only.
    pub detail: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            write!(f, "{}: {}", self.code, self.message)
        } else {
            write!(f, "{}: {}", self.code, self.detail)
        }
    }
}

impl Error {
    /// The Appendix A error for `code`; unknown codes become `tw.internal`.
    pub fn new(code: &str, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        if let Some(&(c, status, message)) = CATALOGUE.iter().find(|row| row.0 == code) {
            return Self { code: c, status, message, detail };
        }
        if let Some(&c) = CLIENT_CODES.iter().find(|c| **c == code) {
            return Self { code: c, status: 0, message: c, detail };
        }
        let (c, status, message) = CATALOGUE[0];
        Self { code: c, status, message, detail }
    }
}

/// The HTTP status of an Appendix A code (500 if unknown).
pub fn status_of(code: &str) -> u16 {
    CATALOGUE.iter().find(|row| row.0 == code).map_or(500, |row| row.1)
}

/// The JSON error body used in every language:
/// `{"error": {"code": ..., "message": ..., "request_id": ...}}`.
pub fn error_body(error: &Error, request_id: Option<&str>) -> Vec<u8> {
    serde_json::json!({
        "error": {"code": error.code, "message": error.message, "request_id": request_id}
    })
    .to_string()
    .into_bytes()
}
