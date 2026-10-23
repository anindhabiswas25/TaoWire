package btauth

import (
	"sync/atomic"
	"time"
)

// NonceSource hands out strictly increasing nonces: max(now_ns, last + 1)
// (spec 11.2 rule 5), safe for concurrent use. The zero value uses the wall
// clock.
type NonceSource struct {
	last atomic.Uint64
	// NowNs replaces the wall clock (tests). nil = time.Now().UnixNano().
	NowNs func() uint64
}

// Next returns a nonce larger than every nonce returned before.
func (n *NonceSource) Next() uint64 {
	for {
		now := n.now()
		last := n.last.Load()
		next := now
		if next <= last {
			next = last + 1
		}
		if n.last.CompareAndSwap(last, next) {
			return next
		}
	}
}

func (n *NonceSource) now() uint64 {
	if n.NowNs != nil {
		return n.NowNs()
	}
	return uint64(time.Now().UnixNano())
}
