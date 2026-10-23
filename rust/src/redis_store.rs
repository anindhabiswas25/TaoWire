//! Redis-backed [`NonceStore`] (feature `redis`) for miners running several
//! processes or hosts for one hotkey. Keys are the Python kit's
//! (`tw:n:<hotkey>:<nonce>`, `SET NX PX`), so Rust, Go and Python miners can
//! share one Redis.

use std::time::Duration;

use redis::aio::ConnectionManager;

use crate::store::{NonceStore, StoreError, StoreFuture};

/// Key prefix of the Python kit's `RedisNonceStore`.
pub const DEFAULT_PREFIX: &str = "tw:n:";

/// A [`NonceStore`] on Redis. A Redis error fails closed
/// (`tw.replay_store_unavailable`).
#[derive(Clone)]
pub struct RedisStore {
    conn: ConnectionManager,
    retention: Duration,
    prefix: String,
}

impl std::fmt::Debug for RedisStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RedisStore(prefix={:?}, retention={:?})", self.prefix, self.retention)
    }
}

impl RedisStore {
    /// Connect to `url` (e.g. `redis://127.0.0.1:6379/0`); `retention` at least 1 ms.
    pub async fn connect(
        url: &str,
        retention: Duration,
        prefix: Option<&str>,
    ) -> Result<Self, StoreError> {
        if retention < Duration::from_millis(1) {
            return Err(StoreError("retention must be at least 1 ms".into()));
        }
        let client = redis::Client::open(url).map_err(|e| StoreError(e.to_string()))?;
        let conn = ConnectionManager::new(client).await.map_err(|e| StoreError(e.to_string()))?;
        Ok(Self { conn, retention, prefix: prefix.unwrap_or(DEFAULT_PREFIX).to_owned() })
    }
}

impl NonceStore for RedisStore {
    fn check_and_store<'a>(&'a self, hotkey: &'a str, nonce: u64) -> StoreFuture<'a> {
        Box::pin(async move {
            let key = format!("{}{hotkey}:{nonce}", self.prefix);
            let ms = u64::try_from(self.retention.as_millis()).unwrap_or(u64::MAX);
            let mut conn = self.conn.clone();
            let set: Option<String> = redis::cmd("SET")
                .arg(&key)
                .arg("1")
                .arg("NX")
                .arg("PX")
                .arg(ms)
                .query_async(&mut conn)
                .await
                .map_err(|e| StoreError(e.to_string()))?;
            Ok(set.is_some())
        })
    }

    fn retention(&self) -> Duration {
        self.retention
    }
}
