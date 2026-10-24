package redisstore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestNewValidates(t *testing.T) {
	if _, err := New(nil, time.Minute, ""); err == nil {
		t.Fatal("nil client accepted")
	}
	c := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer c.Close()
	if _, err := New(c, 0, ""); err == nil {
		t.Fatal("zero retention accepted")
	}
	s, err := New(c, time.Minute, "")
	if err != nil || s.prefix != DefaultPrefix || s.Retention() != time.Minute {
		t.Fatalf("New: %v", err)
	}
}

func TestUnreachableRedisIsAnError(t *testing.T) {
	c := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond, MaxRetries: -1})
	defer c.Close()
	s, _ := New(c, time.Minute, "")
	if _, err := s.CheckAndStore(context.Background(), "hk", 1); err == nil {
		t.Fatal("no error from an unreachable Redis")
	}
}

// TestRealRedis runs against TAOWIRE_TEST_REDIS_URL (the Python suite's
// variable), e.g. redis://127.0.0.1:6379/15.
func TestRealRedis(t *testing.T) {
	url := os.Getenv("TAOWIRE_TEST_REDIS_URL")
	if url == "" {
		t.Skip("TAOWIRE_TEST_REDIS_URL not set")
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	c := redis.NewClient(opts)
	defer c.Close()
	prefix := "tw:test:go:" + time.Now().Format("150405.000000") + ":"
	s, _ := New(c, 2*time.Second, prefix)
	ctx := context.Background()
	first, err := s.CheckAndStore(ctx, "5Grw", 42)
	if err != nil || !first {
		t.Fatalf("first: %v %v", first, err)
	}
	again, err := s.CheckAndStore(ctx, "5Grw", 42)
	if err != nil || again {
		t.Fatalf("replay accepted: %v %v", again, err)
	}
	ttl := c.PTTL(ctx, prefix+"5Grw:42").Val()
	if ttl <= 0 || ttl > 2*time.Second {
		t.Fatalf("ttl %v", ttl)
	}
}
