use std::collections::HashMap;

use crate::error::{codes, Error};
use crate::keys::{verify_signature, Keypair};
use crate::payload::{body_sha256, Scheme};
use crate::ss58::decode_ss58;

/// First line of every twresp/1 payload.
pub const RESP_PROTOCOL: &str = "twresp/1";

/// The twresp/1 signed payload (spec 9.1). `digest` is the sha256 hex of the
/// raw response body, or a stream digest (spec 9.2).
pub fn response_payload(
    scheme: Scheme,
    request_nonce: u64,
    sender: &str,
    responder: &str,
    status: u16,
    digest: &str,
) -> Vec<u8> {
    [
        RESP_PROTOCOL,
        scheme.as_str(),
        &request_nonce.to_string(),
        sender,
        responder,
        &status.to_string(),
        digest,
    ]
    .join("\n")
    .into_bytes()
}

/// The twresp/1 headers for an answer to the request with `request_nonce`
/// from `sender`.
pub fn sign_response(
    key: &Keypair,
    request_nonce: u64,
    sender: &str,
    status: u16,
    body: &[u8],
) -> Vec<(String, String)> {
    let payload = response_payload(
        key.scheme(),
        request_nonce,
        sender,
        key.ss58(),
        status,
        &body_sha256(body),
    );
    let mut h = vec![
        ("X-TW-Resp-Version".to_owned(), "1".to_owned()),
        ("X-TW-Resp-Hotkey".to_owned(), key.ss58().to_owned()),
    ];
    if key.scheme() == Scheme::Ed25519 {
        h.push(("X-TW-Resp-Crypto".to_owned(), "ed25519".to_owned()));
    }
    h.push(("X-TW-Resp-Signature".to_owned(), format!("0x{}", hex::encode(key.sign(&payload)))));
    h
}

/// Check an answer's twresp/1 signature against what this validator sent.
/// Any problem is `tw.bad_response_signature`.
pub fn verify_response<'h>(
    header_pairs: impl IntoIterator<Item = (&'h str, &'h str)>,
    expected_responder: &str,
    request_nonce: u64,
    sender: &str,
    status: u16,
    body: &[u8],
) -> Result<Scheme, Error> {
    verify_response_digest(
        header_pairs,
        expected_responder,
        request_nonce,
        sender,
        status,
        &body_sha256(body),
    )
}

/// [`verify_response`] with the digest given directly (a stream's `tw-end`).
pub fn verify_response_digest<'h>(
    header_pairs: impl IntoIterator<Item = (&'h str, &'h str)>,
    expected_responder: &str,
    request_nonce: u64,
    sender: &str,
    status: u16,
    digest: &str,
) -> Result<Scheme, Error> {
    let bad = |detail: &str| Error::new(codes::BAD_RESPONSE_SIGNATURE, detail);
    let mut h: HashMap<String, &str> = HashMap::new();
    for (name, value) in header_pairs {
        let key = name.to_ascii_lowercase();
        if !key.starts_with("x-tw-resp-") {
            continue;
        }
        if h.insert(key, value).is_some() {
            return Err(bad("duplicate response signature header"));
        }
    }
    match h.get("x-tw-resp-version") {
        None => return Err(bad("response is not signed")),
        Some(&"1") => {}
        Some(_) => return Err(bad("unsupported response signature version")),
    }
    if h.get("x-tw-resp-hotkey") != Some(&expected_responder) {
        return Err(bad("response signed by another hotkey"));
    }
    let scheme = match h.get("x-tw-resp-crypto") {
        None => Scheme::Sr25519,
        Some(c) => {
            Scheme::from_header(c).ok_or_else(|| bad("unsupported response signature scheme"))?
        }
    };
    let sig: [u8; 64] = h
        .get("x-tw-resp-signature")
        .and_then(|s| s.strip_prefix("0x"))
        .filter(|s| s.len() == 128 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .and_then(|s| hex::decode(s).ok())
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| bad("malformed response signature"))?;
    let key = decode_ss58(expected_responder).ok_or_else(|| bad("malformed response signature"))?;
    let payload =
        response_payload(scheme, request_nonce, sender, expected_responder, status, digest);
    if !verify_signature(scheme, &key, &payload, &sig) {
        return Err(bad("invalid response signature"));
    }
    Ok(scheme)
}
