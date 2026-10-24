//! axum middleware (feature `axum`): protect routes with btauth/1.
//!
//! ```ignore
//! let state = Arc::new(MinerAuth::new(verifier).with_response_key(miner_key));
//! let app = Router::new()
//!     .route("/v1/echo", post(echo))
//!     .layer(axum::middleware::from_fn_with_state(state, tensorwire_btauth::axum::protect));
//! // handler: Extension(caller): Extension<Caller>, body: Bytes
//! ```
//!
//! A streaming route (spec 9.2) answers with [`stream_response`], taking the
//! [`StreamContext`] the middleware puts into the request extensions.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{OriginalUri, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use futures_util::{Stream, StreamExt as _};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::error::{codes, error_body, Error};
use crate::keys::Keypair;
use crate::sse::{
    encode_chunk, encode_event, encode_trailer, StreamDigest, StreamLimits, StreamSlot,
    StreamSlots, Trailer, CONTENT_TYPE, EVENT_CHUNK, EVENT_END, TRAILER_RESERVE,
};
use crate::twresp::{response_payload, sign_response};
use crate::verify::{Caller, Verifier};

/// Default request body cap (`TW_MAX_BODY_BYTES`, 1 MiB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1 << 20;
/// Largest handler answer that is buffered for signing (64 MiB).
pub const MAX_SIGNED_RESPONSE_BYTES: usize = 64 << 20;

/// Settings for [`protect`].
#[derive(Debug)]
pub struct MinerAuth {
    verifier: Verifier,
    max_body_bytes: usize,
    response_key: Option<Arc<Keypair>>,
}

impl MinerAuth {
    /// Verify with `verifier`, 1 MiB body cap, answers unsigned.
    pub fn new(verifier: Verifier) -> Self {
        Self { verifier, max_body_bytes: DEFAULT_MAX_BODY_BYTES, response_key: None }
    }

    /// Change the body cap; larger bodies are 413 `tw.payload_too_large`.
    pub fn with_max_body_bytes(mut self, limit: usize) -> Self {
        self.max_body_bytes = limit;
        self
    }

    /// Sign every answer of an authenticated request with twresp/1 (errors
    /// included). Panics if `key` is not the verifier's hotkey.
    pub fn with_response_key(mut self, key: Keypair) -> Self {
        assert_eq!(
            key.ss58(),
            self.verifier.self_hotkey(),
            "response key must be the miner hotkey"
        );
        self.response_key = Some(Arc::new(key));
        self
    }
}

/// An Appendix A error as an axum response (JSON body, unsigned).
pub fn error_response(e: &Error) -> Response {
    let status = StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, [(header::CONTENT_TYPE, "application/json")], error_body(e, None)).into_response()
}

/// The middleware: body cap, btauth/1 verify on the target exactly as received
/// (`OriginalUri` path and query, percent-encoding kept), then the handler with
/// the [`Caller`] and the raw body (`Bytes`) in the request extensions.
/// Absolute-form targets are refused.
pub async fn protect(State(auth): State<Arc<MinerAuth>>, req: Request, next: Next) -> Response {
    let uri =
        req.extensions().get::<OriginalUri>().map_or_else(|| req.uri().clone(), |o| o.0.clone());
    if uri.scheme().is_some() || uri.authority().is_some() {
        return error_response(&Error::new(codes::MALFORMED, "request target must be origin-form"));
    }
    let target = uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > auth.max_body_bytes as u64) {
        return error_response(&Error::new(
            codes::PAYLOAD_TOO_LARGE,
            "Content-Length over the limit",
        ));
    }
    let (mut parts, body) = req.into_parts();
    let body = match to_bytes(body, auth.max_body_bytes).await {
        Ok(b) => b,
        Err(e) => {
            let too_big = std::error::Error::source(&e)
                .is_some_and(|s| s.is::<http_body_util::LengthLimitError>());
            let code = if too_big { codes::PAYLOAD_TOO_LARGE } else { codes::MALFORMED };
            return error_response(&Error::new(code, "body could not be read"));
        }
    };
    let mut pairs = Vec::with_capacity(parts.headers.len());
    for (name, value) in &parts.headers {
        match value.to_str() {
            Ok(v) => pairs.push((name.as_str(), v)),
            Err(_) if name.as_str().starts_with("x-bittensor-") => {
                return error_response(&Error::new(codes::MALFORMED, "header value is not text"));
            }
            Err(_) => {}
        }
    }
    let caller: Caller =
        match auth.verifier.verify(pairs, &body, parts.method.as_str(), &target).await {
            Ok(c) => c,
            Err(e) => return error_response(&e),
        };
    parts.extensions.insert(caller.clone());
    parts.extensions.insert(body.clone());
    parts
        .extensions
        .insert(StreamContext { caller: caller.clone(), key: auth.response_key.clone() });
    let resp = next.run(Request::from_parts(parts, Body::from(body))).await;
    match &auth.response_key {
        None => resp,
        Some(key) => sign(key, &caller, resp).await,
    }
}

async fn sign(key: &Keypair, caller: &Caller, resp: Response) -> Response {
    if resp.extensions().get::<SseStream>().is_some() {
        return resp; // signed by its tw-end trailer, never buffered
    }
    let (mut parts, body) = resp.into_parts();
    let Ok(bytes): Result<Bytes, _> = to_bytes(body, MAX_SIGNED_RESPONSE_BYTES).await else {
        return error_response(&Error::new(codes::INTERNAL, "answer too large to sign"));
    };
    for (name, value) in
        sign_response(key, caller.nonce, &caller.hotkey, parts.status.as_u16(), &bytes)
    {
        if let (Ok(n), Ok(v)) =
            (header::HeaderName::try_from(name.as_str()), HeaderValue::try_from(value.as_str()))
        {
            parts.headers.insert(n, v);
        }
    }
    parts.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    Response::from_parts(parts, Body::from(bytes))
}

/// What [`protect`] puts into the request extensions for a streaming handler:
/// the verified caller and the response key (if answers are signed).
#[derive(Debug, Clone)]
pub struct StreamContext {
    /// The verified caller.
    pub caller: Caller,
    key: Option<Arc<Keypair>>,
}

/// Marks a response built by [`stream_response`]: [`protect`] passes it on
/// unbuffered.
#[derive(Debug, Clone, Copy)]
struct SseStream;

/// Error type a stream source may yield.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Abort reasons of a stream that ended without `tw-end` (spec 9.2, D29).
pub mod abort {
    /// The source yielded an error.
    pub const HANDLER_ERROR: &str = "handler_error";
    /// No chunk within the idle limit.
    pub const IDLE_TIMEOUT: &str = "idle_timeout";
    /// The whole stream took longer than `max_duration`.
    pub const MAX_DURATION: &str = "max_duration";
    /// The next chunk would pass `max_bytes`.
    pub const MAX_BYTES: &str = "max_bytes";
    /// A chunk that is not a JSON object or array, or holds a line break.
    pub const BAD_CHUNK: &str = "bad_chunk";
    /// The client went away.
    pub const CANCELLED: &str = "cancelled";
}

/// Called with `(route, reason)` for every stream that ended without `tw-end`.
pub type AbortHook = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Settings of [`stream_response`].
#[derive(Clone)]
pub struct StreamConfig {
    /// Stream limits (spec 12.1 defaults).
    pub limits: StreamLimits,
    /// Wait for the first chunk at most this long (default 10 s,
    /// `TW_HANDLER_TIMEOUT_S`).
    pub first_chunk_timeout: Duration,
    /// Open streams per caller (D36); share one per process.
    pub slots: Arc<StreamSlots>,
    /// Names the route for [`StreamConfig::on_abort`].
    pub route: String,
    /// E.g. to count `tw_stream_aborted_total{side="miner",reason}`.
    pub on_abort: Option<AbortHook>,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            limits: StreamLimits::default(),
            first_chunk_timeout: Duration::from_secs(10),
            slots: Arc::new(StreamSlots::default()),
            route: String::new(),
            on_abort: None,
        }
    }
}

impl std::fmt::Debug for StreamConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamConfig")
            .field("limits", &self.limits)
            .field("first_chunk_timeout", &self.first_chunk_timeout)
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

/// Answer a protected request with an SSE stream and a signed `tw-end`
/// trailer (spec 9.2). Each item of `source` is one chunk's JSON bytes (an
/// object or array). In order:
///
/// 1. a stream slot for the caller (D36): when the caller holds the maximum,
///    the answer is 429 `tw.rate_limited` with `Retry-After: 1` (signed by
///    [`protect`]) and nothing is streamed;
/// 2. the first item within `first_chunk_timeout`: an error is the signed
///    JSON 500 `tw.handler_error` (an [`Error`] with a status is answered as
///    it is), a stall the signed JSON 504 `tw.handler_timeout`;
/// 3. `200 text/event-stream` with the `X-TW-Resp-*` identity headers, one
///    `chunk` event per item, then `tw-end` (digest, count, signature bound
///    to the request's nonce and sender).
///
/// After the first byte, a source error, a bad chunk, the idle limit, the
/// whole-stream limit, `max_bytes` ([`TRAILER_RESERVE`] kept for the
/// trailer) or a client disconnect ends the stream without `tw-end`, and the
/// abort hook is called. The source is pulled by a task; the response body
/// reads its frames through a one-frame channel, so the task stops at
/// `max_duration` even when the client stops reading (the socket itself is
/// then held by the server until TCP gives up; [`StreamSlots`] bounds how
/// many such streams one caller can hold).
pub async fn stream_response<S>(ctx: &StreamContext, cfg: &StreamConfig, source: S) -> Response
where
    S: Stream<Item = Result<Vec<u8>, BoxError>> + Send + 'static,
{
    let slot = match cfg.slots.acquire(&ctx.caller.hotkey) {
        Ok(slot) => slot,
        Err(e) => {
            let mut resp = error_response(&e);
            resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            return resp;
        }
    };
    let mut source = Box::pin(source);
    let first = match tokio::time::timeout(cfg.first_chunk_timeout, source.next()).await {
        Err(_) => return error_response(&Error::new(codes::HANDLER_TIMEOUT, "no first chunk")),
        Ok(Some(Err(e))) => {
            return match e.downcast::<Error>() {
                Ok(tw) if tw.status != 0 => error_response(&tw),
                _ => error_response(&Error::new(codes::HANDLER_ERROR, "")),
            };
        }
        Ok(Some(Ok(data))) => Some(data),
        Ok(None) => None,
    };
    let (tx, mut rx) = mpsc::channel::<Bytes>(1);
    let producer = Producer {
        ctx: ctx.clone(),
        limits: cfg.limits,
        deadline: Instant::now() + cfg.limits.max_duration(),
        tx,
        _slot: slot,
    };
    let (route, hook) = (cfg.route.clone(), cfg.on_abort.clone());
    tokio::spawn(async move {
        if let Some(reason) = producer.run(first, source).await {
            if let Some(hook) = hook {
                hook(&route, reason);
            }
        }
    });
    let body = futures_util::stream::poll_fn(move |cx| {
        rx.poll_recv(cx).map(|frame| frame.map(Ok::<_, Infallible>))
    });
    let mut resp = Response::new(Body::from_stream(body));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    if let Some(key) = &ctx.key {
        h.insert("x-tw-resp-version", HeaderValue::from_static("1"));
        if let Ok(v) = HeaderValue::from_str(key.ss58()) {
            h.insert("x-tw-resp-hotkey", v);
        }
        if key.scheme() == crate::payload::Scheme::Ed25519 {
            h.insert("x-tw-resp-crypto", HeaderValue::from_static("ed25519"));
        }
    }
    resp.extensions_mut().insert(SseStream);
    resp
}

struct Producer {
    ctx: StreamContext,
    limits: StreamLimits,
    deadline: Instant,
    tx: mpsc::Sender<Bytes>,
    _slot: StreamSlot, // released when the producer ends
}

impl Producer {
    /// Send every chunk and the trailer; the abort reason, or `None` when
    /// `tw-end` was handed over.
    async fn run<S>(
        self,
        first: Option<Vec<u8>>,
        mut source: std::pin::Pin<Box<S>>,
    ) -> Option<&'static str>
    where
        S: Stream<Item = Result<Vec<u8>, BoxError>> + Send,
    {
        let budget = self.limits.max_bytes() - TRAILER_RESERVE;
        let mut digest = StreamDigest::new();
        let mut sent = 0u64;
        let mut item = first;
        while let Some(data) = item.take() {
            let Ok(data) = encode_chunk(&data) else { return Some(abort::BAD_CHUNK) };
            let Ok(frame) = encode_event(EVENT_CHUNK, data) else { return Some(abort::BAD_CHUNK) };
            if sent + frame.len() as u64 > budget {
                return Some(abort::MAX_BYTES);
            }
            sent += frame.len() as u64;
            if let Some(reason) = self.send(frame).await {
                return Some(reason);
            }
            digest.update(data);
            tokio::select! {
                next = source.next() => match next {
                    None => {}
                    Some(Ok(data)) => item = Some(data),
                    Some(Err(_)) => return Some(abort::HANDLER_ERROR),
                },
                () = tokio::time::sleep(self.limits.idle()) => return Some(abort::IDLE_TIMEOUT),
                () = tokio::time::sleep_until(self.deadline) => return Some(abort::MAX_DURATION),
                () = self.tx.closed() => return Some(abort::CANCELLED),
            }
        }
        let signature = self.ctx.key.as_ref().map(|key| {
            let caller = &self.ctx.caller;
            let payload = response_payload(
                key.scheme(),
                caller.nonce,
                &caller.hotkey,
                key.ss58(),
                200,
                &digest.hex(),
            );
            format!("0x{}", hex::encode(key.sign(&payload)))
        });
        let trailer = Trailer { digest: digest.hex(), count: digest.count(), signature };
        if let Ok(frame) = encode_event(EVENT_END, &encode_trailer(&trailer)) {
            // Handed over: a disconnect from here on is no abort.
            let _ = self.send(frame).await;
        }
        None
    }

    async fn send(&self, frame: Vec<u8>) -> Option<&'static str> {
        match tokio::time::timeout_at(self.deadline, self.tx.send(Bytes::from(frame))).await {
            Err(_) => Some(abort::MAX_DURATION),
            Ok(Err(_)) => Some(abort::CANCELLED),
            Ok(Ok(())) => None,
        }
    }
}
