// Package redisstore is a Redis-backed btauth.NonceStore for miners that run
// more than one process or host for one hotkey. Keys are the Python kit's
// ("tw:n:<hotkey>:<nonce>", SET NX PX), so Go and Python miners can share one
// Redis. Kept in its own package so btauth itself needs no Redis client.
package redisstore

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultPrefix is the key prefix of the Python kit's RedisNonceStore.
const DefaultPrefix = "tw:n:"

// Store implements btauth.NonceStore on Redis.
type Store struct {
	client    redis.UniversalClient
	retention time.Duration
	prefix    string
}

// New returns a store on client remembering pairs for retention (at least
// 1 ms). prefix "" means DefaultPrefix.
func New(client redis.UniversalClient, retention time.Duration, prefix string) (*Store, error) {
	if client == nil {
		return nil, errors.New("redisstore: a client is required")
	}
	if retention < time.Millisecond {
		return nil, errors.New("redisstore: retention must be at least 1 ms")
	}
	if prefix == "" {
		prefix = DefaultPrefix
	}
	return &Store{client: client, retention: retention, prefix: prefix}, nil
}

// Retention is how long accepted pairs are remembered.
func (s *Store) Retention() time.Duration { return s.retention }

// CheckAndStore is SET NX with the retention as expiry: true when the pair is
// new. A Redis error is returned as is; the verifier then refuses the request
// with tw.replay_store_unavailable (fail closed).
func (s *Store) CheckAndStore(ctx context.Context, hotkey string, nonce uint64) (bool, error) {
	key := s.prefix + hotkey + ":" + strconv.FormatUint(nonce, 10)
	return s.client.SetNX(ctx, key, "1", s.retention).Result()
}
