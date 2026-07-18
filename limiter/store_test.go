package limiter

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func storeSize(store *RateLimiterMemoryStore) int {
	n := 0
	for i := range store.shards {
		store.shards[i].mutex.Lock()
		n += len(store.shards[i].visitors)
		store.shards[i].mutex.Unlock()
	}
	return n
}

// TestIPv6SameSlash64SharesLimit is the headline security regression: without
// /64 aggregation a single IPv6 client rotates addresses within its own /64 to
// get an unlimited number of buckets, bypassing the limit entirely.
func TestIPv6SameSlash64SharesLimit(t *testing.T) {
	store := newRateLimiterMemoryStore(RateLimiterConfig{Rate: 1, Burst: 1, ExpiresIn: time.Minute})

	a1, _ := store.Allow("2001:db8::1")
	a2, _ := store.Allow("2001:db8::2") // same /64 as the first address

	if !a1 {
		t.Fatal("first request in a /64 should be allowed")
	}
	if a2 {
		t.Fatal("a second address in the same /64 must share the bucket and be denied; otherwise an IPv6 client bypasses the limit by rotating addresses within its own /64")
	}
}

func TestBasicRateLimiting(t *testing.T) {
	store := newRateLimiterMemoryStore(RateLimiterConfig{Rate: 1, Burst: 1, ExpiresIn: time.Minute})
	now := time.Now()
	store.timeNow = func() time.Time { return now }

	if a, _ := store.Allow("192.0.2.1"); !a {
		t.Fatal("first request should be allowed (burst 1)")
	}
	if a, _ := store.Allow("192.0.2.1"); a {
		t.Fatal("second immediate request should be denied")
	}
	now = now.Add(2 * time.Second) // refills at 1/s
	if a, _ := store.Allow("192.0.2.1"); !a {
		t.Fatal("after the bucket refills the request should be allowed again")
	}
}

func TestCanonicalKey(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"ipv4 unchanged", "192.0.2.5", "192.0.2.5"},
		{"ipv6 to /64", "2001:db8::1", "2001:db8::/64"},
		{"ipv6 same /64 different host", "2001:db8::abcd", "2001:db8::/64"},
		{"ipv4-mapped ipv6 unwrapped", "::ffff:192.0.2.5", "192.0.2.5"},
		{"non-ip passes through", "not-an-ip", "not-an-ip"},
	}
	for _, c := range cases {
		if got := canonicalKey(c.in); got != c.want {
			t.Errorf("%s: canonicalKey(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
	if canonicalKey("2001:db8:0:1::1") == canonicalKey("2001:db8:0:2::1") {
		t.Error("addresses in different /64 blocks must map to different keys")
	}
}

func TestIPv4AddressesHaveSeparateLimits(t *testing.T) {
	store := newRateLimiterMemoryStore(RateLimiterConfig{Rate: 1, Burst: 1, ExpiresIn: time.Minute})
	if a, _ := store.Allow("192.0.2.1"); !a {
		t.Fatal("first client should be allowed")
	}
	if a, _ := store.Allow("192.0.2.2"); !a {
		t.Fatal("a distinct IPv4 client must have its own bucket, not share the first client's")
	}
}

func TestDifferentSlash64HaveSeparateLimits(t *testing.T) {
	store := newRateLimiterMemoryStore(RateLimiterConfig{Rate: 1, Burst: 1, ExpiresIn: time.Minute})
	if a, _ := store.Allow("2001:db8:0:1::1"); !a {
		t.Fatal("first /64 should be allowed")
	}
	if a, _ := store.Allow("2001:db8:0:2::1"); !a {
		t.Fatal("a different /64 must have its own bucket")
	}
}

func TestMemoryCapBounded(t *testing.T) {
	// MaxVisitors == numShards → one visitor per shard, so the whole store is
	// capped at numShards regardless of how many distinct keys arrive.
	store := newRateLimiterMemoryStore(RateLimiterConfig{Rate: 100, Burst: 100, ExpiresIn: time.Hour, MaxVisitors: numShards})

	for i := 0; i < 5000; i++ {
		store.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}

	if got := storeSize(store); got > numShards {
		t.Fatalf("the visitor map must stay bounded by MaxVisitors under a distinct-key flood; got %d entries, cap %d", got, numShards)
	}
}

func TestCleanupRemovesStaleVisitors(t *testing.T) {
	store := newRateLimiterMemoryStore(RateLimiterConfig{Rate: 100, Burst: 100, ExpiresIn: time.Minute, MaxVisitors: 100_000})
	now := time.Now()
	store.timeNow = func() time.Time { return now }

	store.Allow("192.0.2.1")
	if got := storeSize(store); got != 1 {
		t.Fatalf("expected 1 tracked visitor, got %d", got)
	}

	now = now.Add(2 * time.Minute)
	sh := store.shardFor(canonicalKey("192.0.2.1"))
	sh.mutex.Lock()
	store.cleanup(sh, now)
	sh.mutex.Unlock()

	if got := storeSize(store); got != 0 {
		t.Fatalf("a visitor idle longer than expiresIn should be cleaned up; got %d", got)
	}
}

// TestConcurrentAllowIsRaceFree drives the sharded store from many goroutines,
// mixing shared and distinct keys, so `go test -race` exercises the locking.
func TestConcurrentAllowIsRaceFree(t *testing.T) {
	store := newRateLimiterMemoryStore(RateLimiterConfig{Rate: 1000, Burst: 1000, ExpiresIn: time.Minute, MaxVisitors: 100_000})

	var wg sync.WaitGroup
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				store.Allow("192.0.2.1")                          // hot shared key
				store.Allow(fmt.Sprintf("10.%d.%d.1", g, i&0xff)) // distinct keys
				store.Allow("2001:db8::1")                        // hot shared /64
			}
		}(g)
	}
	wg.Wait()
}
