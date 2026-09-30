package limiter

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// numShards splits the visitor map so requests for different clients rarely
// contend on the same lock. Must be a power of two (see shardFor).
const numShards = 32

// RateLimiterMemoryStore tracks a token-bucket limiter per client key. It is
// sharded to reduce lock contention, aggregates IPv6 clients by /64 so an
// address-rotating client cannot escape its bucket, and caps the number of
// tracked visitors so a flood of distinct keys cannot exhaust memory.
type RateLimiterMemoryStore struct {
	shards      [numShards]shard
	seed        maphash.Seed
	rate        rate.Limit
	burst       int
	expiresIn   time.Duration
	maxPerShard int
	timeNow     func() time.Time
}

type shard struct {
	mutex       sync.Mutex
	visitors    map[string]*Visitor
	lastCleanup time.Time
}

type Visitor struct {
	*rate.Limiter
	lastSeen time.Time
}

func newRateLimiterMemoryStore(config RateLimiterConfig) *RateLimiterMemoryStore {
	maxPerShard := config.MaxVisitors / numShards
	if maxPerShard < 1 {
		maxPerShard = 1
	}

	store := &RateLimiterMemoryStore{
		seed:        maphash.MakeSeed(),
		rate:        config.Rate,
		burst:       config.Burst,
		expiresIn:   config.ExpiresIn,
		maxPerShard: maxPerShard,
		timeNow:     time.Now,
	}
	for i := range store.shards {
		store.shards[i].visitors = make(map[string]*Visitor)
	}
	return store
}

func (store *RateLimiterMemoryStore) Allow(identifier string) (bool, error) {
	key := canonicalKey(identifier)
	sh := store.shardFor(key)
	now := store.timeNow()

	sh.mutex.Lock()
	defer sh.mutex.Unlock()

	if sh.lastCleanup.IsZero() {
		sh.lastCleanup = now
	}
	if now.Sub(sh.lastCleanup) > store.expiresIn {
		store.cleanup(sh, now)
	}

	visitor, exists := sh.visitors[key]
	if !exists {
		if len(sh.visitors) >= store.maxPerShard {
			store.evictOldest(sh)
		}
		visitor = &Visitor{Limiter: rate.NewLimiter(store.rate, store.burst)}
		sh.visitors[key] = visitor
	}
	visitor.lastSeen = now

	return visitor.AllowN(now, 1), nil
}

func (store *RateLimiterMemoryStore) shardFor(key string) *shard {
	h := maphash.String(store.seed, key)
	return &store.shards[h&(numShards-1)]
}

// cleanup drops visitors idle longer than expiresIn. The caller holds sh.mutex.
func (store *RateLimiterMemoryStore) cleanup(sh *shard, now time.Time) {
	for id, visitor := range sh.visitors {
		if now.Sub(visitor.lastSeen) > store.expiresIn {
			delete(sh.visitors, id)
		}
	}
	sh.lastCleanup = now
}

// evictionSample is how many visitors evictOldest looks at. Map iteration
// starts at a random position, so the oldest of a small sample approximates
// the least recently seen visitor at a fixed cost. A full scan would let a
// flood of new clients (cheap with IPv6 /64s) buy an O(n) pass under the
// shard lock with every request.
const evictionSample = 8

// evictOldest removes the least recently seen of a sample of visitors to
// keep the shard within its cap. The caller holds sh.mutex.
func (store *RateLimiterMemoryStore) evictOldest(sh *shard) {
	var oldestKey string
	var oldestSeen time.Time
	seen := 0
	for id, visitor := range sh.visitors {
		if seen == 0 || visitor.lastSeen.Before(oldestSeen) {
			oldestKey, oldestSeen = id, visitor.lastSeen
		}
		seen++
		if seen == evictionSample {
			break
		}
	}
	if seen > 0 {
		delete(sh.visitors, oldestKey)
	}
}

// canonicalKey normalizes a client IP into a bucket key. IPv6 addresses are
// aggregated to their /64 prefix — the smallest block routinely assigned to a
// single client — so rotating addresses within it cannot create new buckets.
// IPv4 addresses (including IPv4-mapped IPv6) key on the full address.
func canonicalKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is6() {
		if prefix, err := addr.Prefix(64); err == nil {
			return prefix.String()
		}
	}
	return addr.String()
}
