use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The replay store could not be reached; the request is refused with
/// `tw.replay_store_unavailable` (fail closed).
#[derive(Debug, Clone, thiserror::Error)]
#[error("replay store unavailable: {0}")]
pub struct StoreError(pub String);

/// The future a [`NonceStore`] returns.
pub type StoreFuture<'a> = Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + 'a>>;

/// Remembers accepted `(hotkey, nonce)` pairs for [`NonceStore::retention`].
pub trait NonceStore: Send + Sync {
    /// `Ok(true)` when the pair is new (and now recorded), `Ok(false)` on a replay.
    fn check_and_store<'a>(&'a self, hotkey: &'a str, nonce: u64) -> StoreFuture<'a>;
    /// How long pairs are remembered.
    fn retention(&self) -> Duration;
}

#[derive(Default)]
struct Seen {
    set: HashSet<(String, u64)>,
    queue: VecDeque<(Instant, (String, u64))>,
}

/// A [`NonceStore`] for one process. Several processes or hosts serving one
/// hotkey need a shared store (`redis_store`).
pub struct MemoryStore {
    retention: Duration,
    seen: Mutex<Seen>,
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemoryStore(retention={:?})", self.retention)
    }
}

impl MemoryStore {
    /// A store forgetting pairs after `retention`.
    pub fn new(retention: Duration) -> Self {
        Self { retention, seen: Mutex::new(Seen::default()) }
    }

    /// Records the pair at `now`; `false` if it was already recorded.
    pub fn check_and_store_at(&self, hotkey: &str, nonce: u64, now: Instant) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        while seen.queue.front().is_some_and(|(at, _)| *at <= now) {
            if let Some((_, key)) = seen.queue.pop_front() {
                seen.set.remove(&key);
            }
        }
        let key = (hotkey.to_owned(), nonce);
        if seen.set.contains(&key) {
            return false;
        }
        seen.set.insert(key.clone());
        seen.queue.push_back((now + self.retention, key));
        true
    }

    /// Pairs remembered now (expired ones included until the next insert).
    pub fn len(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).set.len()
    }

    /// Whether nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl NonceStore for MemoryStore {
    fn check_and_store<'a>(&'a self, hotkey: &'a str, nonce: u64) -> StoreFuture<'a> {
        let fresh = self.check_and_store_at(hotkey, nonce, Instant::now());
        Box::pin(std::future::ready(Ok(fresh)))
    }

    fn retention(&self) -> Duration {
        self.retention
    }
}
