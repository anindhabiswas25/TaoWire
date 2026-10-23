//! axum middleware (feature `axum`): protect routes with btauth/1.
//!
//! ```ignore
//! let state = Arc::new(MinerAuth::new(verifier).with_response_key(miner_key));
//! let app = Router::new()
//!     .route("/v1/echo", post(echo))
//!     .layer(axum::middleware::from_fn_with_state(state, tensorwire_btauth::axum::protect));
//! // handler: Extension(caller): Extension<Caller>, body: Bytes
//! ```

use std::sync::Arc;

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{OriginalUri, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::{codes, error_body, Error};
use crate::keys::Keypair;
use crate::twresp::sign_response;
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
    response_key: Option<Keypair>,
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
        self.response_key = Some(key);
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
    let resp = next.run(Request::from_parts(parts, Body::from(body))).await;
    match &auth.response_key {
        None => resp,
        Some(key) => sign(key, &caller, resp).await,
    }
}

async fn sign(key: &Keypair, caller: &Caller, resp: Response) -> Response {
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
