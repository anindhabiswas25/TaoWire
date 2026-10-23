package btauth

import (
	"context"
	"sync"
	"time"
)

// NonceStore remembers accepted (hotkey, nonce) pairs for Retention.
// CheckAndStore returns true when the pair is new (and records it), false on
// a replay, and an error when the store cannot be reached (the request is
// then refused with tw.replay_store_unavailable: fail closed).
type NonceStore interface {
	CheckAndStore(ctx context.Context, hotkey string, nonce uint64) (bool, error)
	Retention() time.Duration
}

type storeKey struct {
	hotkey string
	nonce  uint64
}

type expiry struct {
	at  time.Time
	key storeKey
}

// MemoryStore is a NonceStore for one process. Several processes or hosts
// serving one hotkey need a shared store (redisstore).
//
// A pair is forgotten only when Retention has passed on the monotonic clock
// AND its nonce is more than Retention old on the wall clock. Freshness is
// judged on the wall clock, so a backwards wall-clock step (NTP) could
// otherwise make a forgotten nonce fresh again and let a replay through.
type MemoryStore struct {
	retention time.Duration
	now       func() time.Time
	mu        sync.Mutex
	seen      map[storeKey]struct{}
	queue     []expiry // in insertion order, so in expiry order
}

// NewMemoryStore returns a store that forgets pairs after retention.
// now replaces the clock (tests); nil = time.Now.
func NewMemoryStore(retention time.Duration, now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{retention: retention, now: now, seen: map[storeKey]struct{}{}}
}

// Retention is how long accepted pairs are remembered.
func (s *MemoryStore) Retention() time.Duration { return s.retention }

// Len is the number of pairs remembered now.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(s.now())
	return len(s.seen)
}

func (s *MemoryStore) expire(now time.Time) {
	wall := now.UnixNano()
	i := 0
	for i < len(s.queue) && !s.queue[i].at.After(now) && wall-int64(s.queue[i].key.nonce) > int64(s.retention) {
		delete(s.seen, s.queue[i].key)
		i++
	}
	s.queue = s.queue[i:]
}

// CheckAndStore records (hotkey, nonce); false if it was already recorded.
func (s *MemoryStore) CheckAndStore(_ context.Context, hotkey string, nonce uint64) (bool, error) {
	key := storeKey{hotkey, nonce}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expire(now)
	if _, ok := s.seen[key]; ok {
		return false, nil
	}
	s.seen[key] = struct{}{}
	s.queue = append(s.queue, expiry{now.Add(s.retention), key})
	return true, nil
}
