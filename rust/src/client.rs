//! reqwest client (feature `client`): signed requests, verified answers.

use crate::error::{codes, Error};
use crate::keys::Signer;
use crate::payload::Scheme;
use crate::twresp::verify_response;

/// Default cap on an answer body (8 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 << 20;

/// Sends btauth/1-signed requests and verifies twresp/1 answers.
#[derive(Debug)]
pub struct Client {
    signer: Signer,
    http: reqwest::Client,
    max_response_bytes: usize,
}

/// A miner's answer whose twresp/1 signature verified.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// Response headers as text pairs.
    pub headers: Vec<(String, String)>,
    /// Raw body.
    pub body: Vec<u8>,
    /// Scheme of the response signature.
    pub scheme: Scheme,
}

impl Client {
    /// A client over `http` (set its timeout) signing with `signer`.
    pub fn new(signer: Signer, http: reqwest::Client) -> Self {
        Self { signer, http, max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES }
    }

    /// Change the answer cap.
    pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
        self.max_response_bytes = limit;
        self
    }

    /// Send `body` to `url`, signed for the miner hotkey `receiver`, and verify
    /// the answer. Errors use the client codes of Appendix A: `tw.timeout`,
    /// `tw.connect_error`, `tw.response_too_large`, `tw.bad_response_signature`.
    pub async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Vec<u8>,
        receiver: &str,
    ) -> Result<Response, Error> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| Error::new(codes::CONNECT_ERROR, e.to_string()))?;
        let target = match parsed.query() {
            Some(q) => format!("{}?{q}", parsed.path()),
            None => parsed.path().to_owned(),
        };
        let (headers, nonce) = self.signer.sign(method.as_str(), &target, &body, Some(receiver));
        let mut req = self.http.request(method, parsed).body(body);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let net = |e: reqwest::Error| {
            let code = if e.is_timeout() { codes::TIMEOUT } else { codes::CONNECT_ERROR };
            Error::new(code, e.to_string())
        };
        let mut resp = req.send().await.map_err(net)?;
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect();
        let mut data = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(net)? {
            if data.len() + chunk.len() > self.max_response_bytes {
                return Err(Error::new(codes::RESPONSE_TOO_LARGE, "answer over the limit"));
            }
            data.extend_from_slice(&chunk);
        }
        let scheme = verify_response(
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            receiver,
            nonce,
            self.signer.key().ss58(),
            status,
            &data,
        )?;
        Ok(Response { status, headers, body: data, scheme })
    }
}
