//! In-memory token buckets (spec 8.6.2): per hotkey after authentication, per
//! IP before it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Rate and burst of a bucket.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimit {
    /// Tokens added per second.
    pub per_s: f64,
    /// Bucket size.
    pub burst: f64,
}

/// Per hotkey (`TW_RATE_HOTKEY_PER_S` / `_BURST`, spec 12.2).
pub const DEFAULT_HOTKEY_LIMIT: RateLimit = RateLimit { per_s: 20.0, burst: 40.0 };
/// Per IP before authentication (`TW_RATE_IP_PER_S` / `_BURST`).
pub const DEFAULT_IP_LIMIT: RateLimit = RateLimit { per_s: 50.0, burst: 100.0 };

const SWEEP_MIN: usize = 10_000;

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Duration,
}

struct State {
    buckets: HashMap<String, Bucket>,
    sweep_at: usize,
}

/// Token buckets keyed by a string; full buckets are dropped, so the map
/// holds only keys that spent tokens recently. Safe to share.
pub struct TokenBuckets {
    limit: RateLimit,
    now: Arc<dyn Fn() -> Duration + Send + Sync>,
    state: Mutex<State>,
}

impl std::fmt::Debug for TokenBuckets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBuckets").field("limit", &self.limit).finish_non_exhaustive()
    }
}

impl TokenBuckets {
    /// Buckets with `limit` on the monotonic clock.
    pub fn new(limit: RateLimit) -> Result<Self, String> {
        let start = Instant::now();
        Self::with_clock(limit, Arc::new(move || start.elapsed()))
    }

    /// Buckets with `limit` on `now` (tests).
    pub fn with_clock(
        limit: RateLimit,
        now: Arc<dyn Fn() -> Duration + Send + Sync>,
    ) -> Result<Self, String> {
        if !(limit.per_s > 0.0 && limit.burst >= 1.0 && (limit.per_s + limit.burst).is_finite()) {
            return Err("per_s must be > 0 and burst >= 1".into());
        }
        Ok(Self {
            limit,
            now,
            state: Mutex::new(State { buckets: HashMap::new(), sweep_at: SWEEP_MIN }),
        })
    }

    /// Take one token for `key`: 0 when allowed, else the whole seconds until
    /// one is available (at least 1, for `Retry-After`).
    pub fn take(&self, key: &str) -> u64 {
        let now = (self.now)();
        let l = self.limit;
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let b = st.buckets.get(key).copied().unwrap_or(Bucket { tokens: l.burst, at: now });
        let tokens = l.burst.min(b.tokens + now.saturating_sub(b.at).as_secs_f64() * l.per_s);
        if tokens < 1.0 {
            st.buckets.insert(key.to_owned(), Bucket { tokens, at: now });
            // tokens < 1 and per_s > 0: a positive, finite wait
            return (((1.0 - tokens) / l.per_s).ceil() as u64).max(1);
        }
        st.buckets.insert(key.to_owned(), Bucket { tokens: tokens - 1.0, at: now });
        if st.buckets.len() > st.sweep_at {
            st.buckets.retain(|_, v| {
                v.tokens + now.saturating_sub(v.at).as_secs_f64() * l.per_s < l.burst
            });
            // Next sweep only after the map has doubled: O(1) amortised per take.
            st.sweep_at = SWEEP_MIN.max(st.buckets.len() * 2);
        }
        0
    }

    /// Buckets held (tests, metrics).
    pub fn len(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).buckets.len()
    }

    /// Whether no bucket is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_refill_and_sweep() {
        let t = Arc::new(Mutex::new(Duration::ZERO));
        let clock = Arc::clone(&t);
        let b = TokenBuckets::with_clock(
            RateLimit { per_s: 2.0, burst: 3.0 },
            Arc::new(move || *clock.lock().unwrap()),
        )
        .unwrap();
        assert_eq!((b.take("a"), b.take("a"), b.take("a")), (0, 0, 0));
        assert_eq!(b.take("a"), 1);
        assert_eq!(b.take("b"), 0);
        *t.lock().unwrap() += Duration::from_millis(500);
        assert_eq!(b.take("a"), 0);
        for bad in [RateLimit { per_s: 0.0, burst: 1.0 }, RateLimit { per_s: 1.0, burst: 0.5 }] {
            assert!(TokenBuckets::new(bad).is_err());
        }
        let clock = Arc::clone(&t);
        let slow = TokenBuckets::with_clock(
            RateLimit { per_s: 0.1, burst: 1.0 },
            Arc::new(move || *clock.lock().unwrap()),
        )
        .unwrap();
        slow.take("x");
        assert_eq!(slow.take("x"), 10);
        let clock = Arc::clone(&t);
        let many = TokenBuckets::with_clock(
            RateLimit { per_s: 1000.0, burst: 2.0 },
            Arc::new(move || *clock.lock().unwrap()),
        )
        .unwrap();
        for i in 0..SWEEP_MIN {
            many.take(&i.to_string());
        }
        *t.lock().unwrap() += Duration::from_secs(1);
        many.take("trigger");
        assert_eq!(many.len(), 1);
        assert!(!many.is_empty());
        assert_eq!(TokenBuckets::new(DEFAULT_IP_LIMIT).unwrap().take("ip"), 0);
        let _ = format!("{b:?}");
    }
}
