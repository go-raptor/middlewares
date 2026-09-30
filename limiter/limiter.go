package limiter

import (
	"math"
	"strconv"
	"time"

	"github.com/go-raptor/raptor/v4/core"
	"github.com/go-raptor/raptor/v4/errs"
	"golang.org/x/time/rate"
)

type RateLimiterConfig struct {
	Rate      rate.Limit    `yaml:"rate"`
	Burst     int           `yaml:"burst"`
	ExpiresIn time.Duration `yaml:"expires_in"`
	// MaxVisitors caps how many distinct clients are tracked, bounding memory
	// under a flood of distinct keys. 0 applies the default.
	MaxVisitors int `yaml:"max_visitors"`
}

// DefaultRateLimiterConfig allows 20 requests per second per client IP, with a
// burst of 20. That suits general API throttling but does nothing against
// password guessing; scope a much stricter limiter to the login action (see
// the README).
var DefaultRateLimiterConfig = RateLimiterConfig{
	Rate:        20,
	Burst:       0,
	ExpiresIn:   3 * time.Minute,
	MaxVisitors: 100_000,
}

type RateLimiterMiddleware struct {
	core.Middleware
	config            RateLimiterConfig
	store             *RateLimiterMemoryStore
	retryAfterSeconds int
}

func NewRateLimiterMiddleware(config RateLimiterConfig) *RateLimiterMiddleware {
	return &RateLimiterMiddleware{
		config: config,
	}
}

func (m *RateLimiterMiddleware) Init(r *core.Resources) {
	m.Middleware.Init(r)

	if m.config.Rate == 0 {
		m.config.Rate = DefaultRateLimiterConfig.Rate
	}
	if m.config.ExpiresIn == 0 {
		m.config.ExpiresIn = DefaultRateLimiterConfig.ExpiresIn
	}
	if m.config.MaxVisitors == 0 {
		m.config.MaxVisitors = DefaultRateLimiterConfig.MaxVisitors
	}
	if m.config.Burst == 0 {
		// A fractional rate truncates to 0, which would make a zero-burst
		// limiter reject every request; never go below 1.
		m.config.Burst = max(1, int(m.config.Rate))
	}

	m.retryAfterSeconds = retryAfterSeconds(m.config.Rate)
	m.store = newRateLimiterMemoryStore(m.config)
	r.Log.Info("RateLimiterMiddleware initialized")
}

func (m *RateLimiterMiddleware) Handle(c *core.Context, next func(*core.Context) error) error {
	ip := c.RealIP()
	if ip == "" {
		m.Log.Warn("Unable to extract client IP")
		return errs.NewErrorForbidden("Unable to identify client")
	}

	allow, err := m.store.Allow(ip)
	if err != nil {
		m.Log.Error("Rate limiter error", "ip", ip, "error", err)
		return errs.NewErrorInternal("Rate limiter error")
	}

	if !allow {
		// Debug, not warn: the logger middleware records every 429 already.
		m.Log.Debug("Rate limit exceeded", "ip", ip)
		c.Response().Header().Set(core.HeaderRetryAfter, strconv.Itoa(m.retryAfterSeconds))
		return errs.NewErrorTooManyRequests("Rate limit exceeded")
	}

	return next(c)
}

// retryAfterSeconds is a coarse hint for the Retry-After header: how long until
// roughly one token is available again, in whole seconds, at least 1.
func retryAfterSeconds(r rate.Limit) int {
	if r <= 0 {
		return 1
	}
	if s := int(math.Ceil(1 / float64(r))); s > 1 {
		return s
	}
	return 1
}
