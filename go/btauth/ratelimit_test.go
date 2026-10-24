package btauth

import (
	"fmt"
	"testing"
	"time"
)

func TestTokenBuckets(t *testing.T) {
	var now time.Duration
	b, err := NewTokenBuckets(RateLimit{PerS: 2, Burst: 3}, func() time.Duration { return now })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if w := b.Take("a"); w != 0 {
			t.Fatal(i, w)
		}
	}
	if w := b.Take("a"); w != 1 {
		t.Fatal("empty bucket must wait", w)
	}
	if b.Take("b") != 0 {
		t.Fatal("keys are separate")
	}
	now += 500 * time.Millisecond
	if b.Take("a") != 0 {
		t.Fatal("refilled one token")
	}
	for _, bad := range []RateLimit{{0, 1}, {1, 0.5}, {-1, 2}} {
		if _, err := NewTokenBuckets(bad, nil); err == nil {
			t.Error(bad)
		}
	}
	slow, _ := NewTokenBuckets(RateLimit{PerS: 0.1, Burst: 1}, func() time.Duration { return now })
	slow.Take("x")
	if w := slow.Take("x"); w != 10 {
		t.Fatal(w)
	}
	real, _ := NewTokenBuckets(DefaultIPLimit, nil)
	if real.Take("ip") != 0 {
		t.Fatal("default clock")
	}
}

func TestTokenBucketsSweepFullBuckets(t *testing.T) {
	var now time.Duration
	b, _ := NewTokenBuckets(RateLimit{PerS: 1000, Burst: 2}, func() time.Duration { return now })
	for i := 0; i < sweepMin; i++ {
		b.Take(fmt.Sprint(i))
	}
	now += time.Second // every bucket is full again
	b.Take("trigger")
	if n := b.Len(); n != 1 {
		t.Fatalf("%d buckets after the sweep", n)
	}
}
