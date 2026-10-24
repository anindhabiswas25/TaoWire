//! reqwest client (feature `client`): signed requests, verified answers.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::time::Instant;

use crate::error::{codes, Error};
use crate::keys::Signer;
use crate::payload::Scheme;
use crate::sse::{
    decode_chunk, parse_trailer, Event, Parser, StreamDigest, StreamLimits, Trailer, CONTENT_TYPE,
    EVENT_CHUNK, EVENT_END,
};
use crate::twresp::{verify_response, verify_response_digest};

/// Default time budget of one query (`TW_QUERY_TIMEOUT_S`, 12 s, spec 8.8).
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(12);

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

    /// Start one streaming query (spec 9.2) and return the open stream once
    /// its head arrived. `budget` is the query's time budget (connection and
    /// head; the stream then ends by the budget left or the limits'
    /// `max_duration`, whichever comes first). A per-request timeout of the
    /// budget replaces the reqwest client's own; do not give the reqwest
    /// client a read timeout shorter than the idle limit.
    ///
    /// An answer that is not a 200 event stream is read whole and returned as
    /// an error: the miner's `tw.*` code from its error body (verified when
    /// signed), `tw.http_<status>` otherwise, `tw.invalid_response` for a
    /// verified 200 that is not a stream, `tw.bad_response_signature` for a
    /// bad signature.
    pub async fn stream(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Vec<u8>,
        receiver: &str,
        limits: StreamLimits,
        budget: Duration,
    ) -> Result<Stream, Error> {
        let started = Instant::now();
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| Error::new(codes::CONNECT_ERROR, e.to_string()))?;
        let target = match parsed.query() {
            Some(q) => format!("{}?{q}", parsed.path()),
            None => parsed.path().to_owned(),
        };
        let (headers, nonce) = self.signer.sign(method.as_str(), &target, &body, Some(receiver));
        let mut req = self
            .http
            .request(method, parsed)
            .header("accept", CONTENT_TYPE)
            .header("accept-encoding", "identity")
            // Our own deadline ends the stream; this only bounds a stuck client.
            .timeout(budget + Duration::from_secs(1));
        if !body.is_empty() {
            req = req.header("content-type", "application/json");
        }
        req = req.body(body);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let net = |e: reqwest::Error| {
            let code = if e.is_timeout() { codes::TIMEOUT } else { codes::CONNECT_ERROR };
            Error::new(code, e.to_string())
        };
        let resp = match tokio::time::timeout(budget, req.send()).await {
            Err(_) => return Err(Error::new(codes::TIMEOUT, "time budget exhausted")),
            Ok(r) => r.map_err(net)?,
        };
        if resp.url().as_str() != url && reqwest::Url::parse(url).ok().as_ref() != Some(resp.url())
        {
            // The reqwest client followed a redirect (build it with
            // `redirect(Policy::none())`): never trust that answer.
            return Err(Error::new(codes::INVALID_RESPONSE, "the stream was redirected"));
        }
        let status = resp.status().as_u16();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect();
        let is_stream = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|m| m.trim().eq_ignore_ascii_case(CONTENT_TYPE));
        if status != 200 || !is_stream {
            let left = budget.saturating_sub(started.elapsed());
            let data = match tokio::time::timeout(left, self.read_body(resp)).await {
                Err(_) => return Err(Error::new(codes::TIMEOUT, "time budget exhausted")),
                Ok(r) => r?,
            };
            return Err(self.not_a_stream(status, &headers, &data, receiver, nonce));
        }
        let find = |name: &str| headers.iter().filter(|(k, _)| k == name).count();
        if find("content-encoding") > 0 {
            return Err(Error::new(codes::INVALID_RESPONSE, "encoded event stream"));
        }
        if find("x-tw-resp-signature") > 0 {
            return Err(Error::new(
                codes::BAD_RESPONSE_SIGNATURE,
                "signature header at stream start",
            ));
        }
        let version_ok = headers.iter().any(|(k, v)| k == "x-tw-resp-version" && v == "1");
        if !version_ok || find("x-tw-resp-hotkey") == 0 {
            return Err(Error::new(
                codes::BAD_RESPONSE_SIGNATURE,
                "X-TW-Resp-* missing at stream start",
            ));
        }
        let left = budget.saturating_sub(started.elapsed()).min(limits.max_duration());
        Ok(Stream {
            resp,
            headers,
            limits,
            deadline: Instant::now() + left,
            responder: receiver.to_owned(),
            sender: self.signer.key().ss58().to_owned(),
            nonce,
            parser: Parser::new(),
            pending: std::collections::VecDeque::new(),
            digest: StreamDigest::new(),
            received: 0,
            trailer: None,
            eof: false,
            chunks: Vec::new(),
            failed: None,
        })
    }

    async fn read_body(&self, mut resp: reqwest::Response) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        while let Some(chunk) =
            resp.chunk().await.map_err(|e| Error::new(codes::INVALID_RESPONSE, e.to_string()))?
        {
            if data.len() + chunk.len() > self.max_response_bytes {
                return Err(Error::new(codes::RESPONSE_TOO_LARGE, "answer over the limit"));
            }
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }

    fn not_a_stream(
        &self,
        status: u16,
        headers: &[(String, String)],
        data: &[u8],
        receiver: &str,
        nonce: u64,
    ) -> Error {
        let signed = headers.iter().any(|(k, _)| k == "x-tw-resp-signature");
        if signed || status == 200 {
            let pairs = headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));
            if let Err(e) =
                verify_response(pairs, receiver, nonce, self.signer.key().ss58(), status, data)
            {
                return e;
            }
        }
        if status == 200 {
            return Error::new(codes::INVALID_RESPONSE, "answer is not an event stream");
        }
        answer_error(status, data)
    }
}

/// The miner's `tw.*` code from an error body, else `tw.http_<status>`.
fn answer_error(status: u16, body: &[u8]) -> Error {
    let code = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"]["code"].as_str().map(str::to_owned));
    if let Some(code) = code {
        let e = Error::new(&code, "answered by the miner");
        if e.code == code && e.status != 0 {
            return e;
        }
    }
    let code = http_code(status);
    Error { code, status: 0, message: code, detail: String::new() }
}

/// `tw.http_<status>` as a `'static` code: one string per status, at most
/// one per possible status value.
fn http_code(status: u16) -> &'static str {
    static CODES: OnceLock<Mutex<HashMap<u16, &'static str>>> = OnceLock::new();
    let mut codes = CODES.get_or_init(Mutex::default).lock().unwrap_or_else(|p| p.into_inner());
    codes.entry(status).or_insert_with(|| Box::leak(format!("tw.http_{status}").into_boxed_str()))
}

/// One chunk as it arrived. **Not verified**: trust it only when the
/// stream's [`Stream::next`] returned `Ok(None)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedChunk {
    /// Position in the stream.
    pub index: u64,
    /// The chunk's exact `data` bytes (a JSON object or array; what the
    /// digest covers).
    pub data: Vec<u8>,
}

/// One streaming query (spec 9.2), from [`Client::stream`].
///
/// ```ignore
/// let mut s = client.stream(Method::POST, url, body, miner, StreamLimits::default(), budget).await?;
/// while let Some(chunk) = s.next().await? { /* unverified */ }
/// // Ok(None): tw-end matched and verified; s.chunks() can be trusted now.
/// ```
///
/// The rules: at most `max_bytes` on the wire (`tw.response_too_large`); the
/// deadline and the idle limit between two complete events (`tw.timeout`) —
/// the idle clock restarts on every call of [`Stream::next`], so the caller's
/// own time with a chunk does not count, and no other read timeout applies;
/// every chunk a JSON object or array (`tw.invalid_response`); and
/// `tw.bad_response_signature` for the whole stream when `tw-end` is missing,
/// malformed, repeated or followed by another event, when count or digest do
/// not match, or when its signature does not verify for this request.
/// Unknown events and comments are ignored.
#[derive(Debug)]
pub struct Stream {
    resp: reqwest::Response,
    headers: Vec<(String, String)>,
    limits: StreamLimits,
    deadline: Instant,
    responder: String,
    sender: String,
    nonce: u64,
    parser: Parser,
    pending: std::collections::VecDeque<Event>,
    digest: StreamDigest,
    received: u64,
    trailer: Option<Trailer>,
    eof: bool,
    chunks: Vec<Vec<u8>>,
    failed: Option<Error>,
}

impl Stream {
    /// The next chunk (`Ok(Some)`, unverified), the verified end (`Ok(None)`),
    /// or the error that rejects the whole stream (returned again on later
    /// calls).
    pub async fn next(&mut self) -> Result<Option<UnverifiedChunk>, Error> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        let r = self.advance().await;
        if let Err(e) = &r {
            self.failed = Some(e.clone());
        }
        r
    }

    async fn advance(&mut self) -> Result<Option<UnverifiedChunk>, Error> {
        // The idle clock starts now: the caller's time is not the miner's.
        let mut idle_at = Instant::now() + self.limits.idle();
        loop {
            while let Some(ev) = self.pending.pop_front() {
                if let Some(chunk) = self.event(ev)? {
                    return Ok(Some(chunk));
                }
                idle_at = Instant::now() + self.limits.idle();
            }
            if self.eof {
                return match self.trailer {
                    Some(_) => Ok(None),
                    None => Err(Error::new(
                        codes::BAD_RESPONSE_SIGNATURE,
                        "stream ended without tw-end",
                    )),
                };
            }
            let until = idle_at.min(self.deadline);
            let piece = match tokio::time::timeout_at(until, self.resp.chunk()).await {
                Err(_) => return Err(Error::new(codes::TIMEOUT, "stream limit reached")),
                Ok(Err(e)) if e.is_timeout() => {
                    return Err(Error::new(codes::TIMEOUT, "stream limit reached"))
                }
                // Cut mid-stream (e.g. the miner aborted): no valid tw-end.
                Ok(Err(_)) => {
                    return Err(Error::new(
                        codes::BAD_RESPONSE_SIGNATURE,
                        "stream broken before tw-end",
                    ))
                }
                Ok(Ok(piece)) => piece,
            };
            match piece {
                None => {
                    self.eof = true;
                    self.pending.extend(self.parser.finish());
                }
                Some(bytes) => {
                    self.received += bytes.len() as u64;
                    if self.received > self.limits.max_bytes() {
                        return Err(Error::new(codes::RESPONSE_TOO_LARGE, "stream over max_bytes"));
                    }
                    self.pending.extend(self.parser.feed(&bytes));
                }
            }
        }
    }

    fn event(&mut self, ev: Event) -> Result<Option<UnverifiedChunk>, Error> {
        let bad = |detail: &str| Error::new(codes::BAD_RESPONSE_SIGNATURE, detail);
        if self.trailer.is_some() {
            return Err(bad("event after tw-end"));
        }
        match ev.event.as_str() {
            EVENT_CHUNK => {
                decode_chunk(&ev.data)
                    .map_err(|e| Error::new(codes::INVALID_RESPONSE, e.to_string()))?;
                let index = self.digest.count();
                self.digest.update(&ev.data);
                self.chunks.push(ev.data.clone());
                Ok(Some(UnverifiedChunk { index, data: ev.data }))
            }
            EVENT_END => {
                let t = parse_trailer(&ev.data).map_err(|e| bad(&e.to_string()))?;
                if t.count != self.digest.count() {
                    return Err(bad("chunk count mismatch"));
                }
                if t.digest != self.digest.hex() {
                    return Err(bad("stream digest mismatch"));
                }
                let sig = t.signature.as_deref().ok_or_else(|| bad("tw-end is not signed"))?;
                let pairs = self
                    .headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .chain([("x-tw-resp-signature", sig)]);
                verify_response_digest(
                    pairs,
                    &self.responder,
                    self.nonce,
                    &self.sender,
                    200,
                    &t.digest,
                )?;
                self.trailer = Some(t);
                Ok(None)
            }
            _ => Ok(None), // unknown events are ignored
        }
    }

    /// Every chunk read so far, in order. Trust them only after
    /// [`Stream::next`] returned `Ok(None)`.
    pub fn chunks(&self) -> &[Vec<u8>] {
        &self.chunks
    }

    /// Read to the end: every chunk once the trailer verified.
    pub async fn finish(mut self) -> Result<Vec<Vec<u8>>, Error> {
        while self.next().await?.is_some() {}
        Ok(self.chunks)
    }
}
