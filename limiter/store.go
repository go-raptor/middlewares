package limiter

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimiterMemoryStore struct {
	visitors    map[string]*Visitor
	mutex       sync.Mutex
	rate        rate.Limit
	burst       int
	expiresIn   time.Duration
	lastCleanup time.Time
	timeNow     func() time.Time
}

type Visitor struct {
	*rate.Limiter
	lastSeen time.Time
}

func newRateLimiterMemoryStore(config RateLimiterConfig) *RateLimiterMemoryStore {
	store := &RateLimiterMemoryStore{
		rate:      config.Rate,
		burst:     config.Burst,
		expiresIn: config.ExpiresIn,
		visitors:  make(map[string]*Visitor),
		timeNow:   time.Now,
	}
	store.lastCleanup = store.timeNow()
	return store
}

func (store *RateLimiterMemoryStore) Allow(identifier string) (bool, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	limiter, exists := store.visitors[identifier]
	if !exists {
		limiter = &Visitor{
			Limiter: rate.NewLimiter(store.rate, store.burst),
		}
		store.visitors[identifier] = limiter
	}

	now := store.timeNow()
	limiter.lastSeen = now

	if now.Sub(store.lastCleanup) > store.expiresIn {
		store.cleanupStaleVisitors()
	}

	return limiter.Limiter.AllowN(now, 1), nil
}

func (store *RateLimiterMemoryStore) cleanupStaleVisitors() {
	for id, visitor := range store.visitors {
		if store.timeNow().Sub(visitor.lastSeen) > store.expiresIn {
			delete(store.visitors, id)
		}
	}
	store.lastCleanup = store.timeNow()
}
