package btauth

import (
	"errors"
	"math"
	"sync"
	"time"
)

// RateLimit is the rate and burst of a token bucket (spec 8.6.2).
type RateLimit struct {
	PerS  float64 // tokens added per second
	Burst float64 // bucket size
}

// Defaults of spec 12.2: per hotkey (TW_RATE_HOTKEY_PER_S / _BURST) and per
// IP before authentication (TW_RATE_IP_PER_S / _BURST).
var (
	DefaultHotkeyLimit = RateLimit{PerS: 20, Burst: 40}
	DefaultIPLimit     = RateLimit{PerS: 50, Burst: 100}
)

// sweepMin is the map size at which full buckets are first dropped.
const sweepMin = 10_000

type bucket struct {
	tokens float64
	at     time.Duration // monotonic time of the last update
}

// TokenBuckets are in-memory token buckets keyed by a string (a hotkey and
// route, or an IP). Full buckets are dropped, so the map holds only keys that
// spent tokens recently. Safe for concurrent use.
type TokenBuckets struct {
	limit   RateLimit
	now     func() time.Duration
	mu      sync.Mutex
	buckets map[string]bucket
	sweepAt int
}

// NewTokenBuckets returns buckets with limit; now replaces the monotonic
// clock (nil = time since the buckets were made).
func NewTokenBuckets(limit RateLimit, now func() time.Duration) (*TokenBuckets, error) {
	if !(limit.PerS > 0) || !(limit.Burst >= 1) || math.IsInf(limit.PerS+limit.Burst, 0) {
		return nil, errors.New("btauth: PerS must be > 0 and Burst >= 1")
	}
	if now == nil {
		start := time.Now()
		now = func() time.Duration { return time.Since(start) }
	}
	return &TokenBuckets{limit: limit, now: now, buckets: map[string]bucket{}, sweepAt: sweepMin}, nil
}

// Take takes one token for key: 0 when allowed, else the whole seconds until
// one is available (at least 1, for Retry-After).
func (t *TokenBuckets) Take(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	b, ok := t.buckets[key]
	if !ok {
		b = bucket{tokens: t.limit.Burst, at: now}
	}
	tokens := math.Min(t.limit.Burst, b.tokens+(now-b.at).Seconds()*t.limit.PerS)
	if tokens < 1 {
		t.buckets[key] = bucket{tokens: tokens, at: now}
		return max(1, int(math.Ceil((1-tokens)/t.limit.PerS)))
	}
	t.buckets[key] = bucket{tokens: tokens - 1, at: now}
	if len(t.buckets) > t.sweepAt {
		for k, v := range t.buckets {
			if v.tokens+(now-v.at).Seconds()*t.limit.PerS >= t.limit.Burst {
				delete(t.buckets, k)
			}
		}
		// Next sweep only after the map has doubled: O(1) amortised per take.
		t.sweepAt = max(sweepMin, len(t.buckets)*2)
	}
	return 0
}

// Len returns the number of buckets held (tests, metrics).
func (t *TokenBuckets) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.buckets)
}
