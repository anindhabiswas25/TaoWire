package btauth

import (
	"sync"
	"time"
)

// stepGuard detects backwards wall-clock steps (spec 8.4.3-8.4.4, D21).
//
// Freshness is judged on the wall clock, but a NonceStore forgets pairs on its
// own clock (the monotonic clock for MemoryStore, Redis' clock for
// redisstore). If the wall clock steps back by more than the store's margin,
// Retention - (MaxAge + AllowedSkew), a forgotten nonce could look fresh
// again. The guard compares wall - monotonic with its previous value on every
// request that reaches the replay check; a drop larger than the margin opens
// a fail-closed window of Retention, during which those requests get
// tw.replay_store_unavailable instead of consulting the store.
type stepGuard struct {
	margin   int64 // ns
	hold     int64 // ns
	wallNs   func() int64
	monoNs   func() int64
	mu       sync.Mutex
	offset   int64
	until    int64 // monotonic ns; 0 = no window
	lastStep int64
}

func newStepGuard(margin, hold time.Duration, wallNs, monoNs func() int64) *stepGuard {
	g := &stepGuard{margin: int64(margin), hold: int64(hold), wallNs: wallNs, monoNs: monoNs}
	g.offset = wallNs() - monoNs()
	return g
}

// check measures now and reports whether the fail-closed window is open.
func (g *stepGuard) check() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	mono := g.monoNs()
	offset := g.wallNs() - mono
	step := g.offset - offset
	g.offset = offset
	if step > g.margin {
		g.until = mono + g.hold
		g.lastStep = step
	}
	return g.until != 0 && mono < g.until
}

// realClocks returns the wall clock (Unix ns) and a monotonic clock (ns since
// the call), both from Go's time.Now, which carries a monotonic reading.
func realClocks() (wall, mono func() int64) {
	start := time.Now()
	return func() int64 { return time.Now().UnixNano() },
		func() int64 { return int64(time.Since(start)) }
}
