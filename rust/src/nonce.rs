use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Strictly increasing nonces: `max(now_ns, last + 1)` (spec 11.2 rule 5),
/// safe to share between threads.
pub struct NonceSource {
    last: AtomicU64,
    now_ns: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for NonceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NonceSource(last={})", self.last.load(Ordering::Relaxed))
    }
}

impl Default for NonceSource {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn wall_clock_ns() -> u64 {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl NonceSource {
    /// Nonces from the wall clock.
    pub fn new() -> Self {
        Self::with_clock(wall_clock_ns)
    }

    /// Nonces from `now_ns` (tests).
    pub fn with_clock(now_ns: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self { last: AtomicU64::new(0), now_ns: Box::new(now_ns) }
    }

    /// A nonce larger than every nonce returned before.
    pub fn next(&self) -> u64 {
        let now = (self.now_ns)();
        let prev = self
            .last
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |last| {
                Some(if now > last { now } else { last + 1 })
            })
            .unwrap_or_else(|last| last); // the closure always returns Some
        if now > prev {
            now
        } else {
            prev + 1
        }
    }
}
