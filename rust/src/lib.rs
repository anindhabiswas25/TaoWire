//! btauth/1 signed requests and twresp/1 signed responses for Bittensor v11
//! subnets, the Rust package of TensorWire (spec Sections 4, 9.1 and 11.5).
//!
//! A miner protects its routes with the [`axum`] layer (feature `axum`): body
//! cap, verification in the normative order (shape, receiver, freshness,
//! signature, replay; the nonce is stored only after the signature verifies),
//! the verified [`Caller`] in the request extensions, and twresp/1 on every
//! answer when a response key is set. A validator signs requests with
//! [`Signer`] and checks answers with [`verify_response`]; feature `client`
//! adds a reqwest [`client::Client`] doing both. Feature `redis` adds a shared
//! [`redis_store::RedisStore`].
//!
//! The verifier is stricter than the Bittensor SDK, like every TensorWire
//! implementation: prefix-42 SS58 senders only, no repeated `X-Bittensor-*`
//! header, nonces of 1 to 20 ASCII digits, the crypto header exactly
//! `ed25519` or `sr25519`, hex-only signatures, never a `<Bytes>`-wrapped
//! signature, and no weak public keys. Every rule has a vector in
//! `conformance/vectors/negative.json`.
//!
//! ed25519 uses `ed25519-dalek` `verify` (RFC 8032, cofactorless), not
//! `verify_strict`, plus an explicit weak-key refusal (ADR-0010).
#![forbid(unsafe_code)]

mod clockstep;
mod error;
mod keys;
mod nonce;
mod payload;
mod ss58;
pub mod sse;
mod store;
mod twresp;
mod verify;

#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "redis")]
pub mod redis_store;
#[cfg(feature = "sidecar")]
pub mod sidecar;

pub use error::{codes, error_body, status_of, Error};
pub use keys::{is_weak_public_key, Keypair, Signer};
pub use nonce::NonceSource;
pub use payload::{body_sha256, build_payload, Scheme, PROTOCOL};
pub use ss58::{decode_ss58, encode_ss58, SS58_PREFIX};
pub use store::{MemoryStore, NonceStore, StoreError, StoreFuture};
pub use twresp::{
    response_payload, sign_response, verify_response, verify_response_digest, RESP_PROTOCOL,
};
pub use verify::{
    headers, Caller, Config, PolicyFn, Verifier, DEFAULT_ALLOWED_SKEW, DEFAULT_MAX_AGE,
};
