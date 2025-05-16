package limiter

import (
	"time"

	"github.com/go-raptor/raptor/v4/core"
	"github.com/go-raptor/raptor/v4/errs"
	"golang.org/x/time/rate"
)

type RateLimiterConfig struct {
	Rate      rate.Limit    `yaml:"rate"`
	Burst     int           `yaml:"burst"`
	ExpiresIn time.Duration `yaml:"expires_in"`
}

var DefaultRateLimiterConfig = RateLimiterConfig{
	Rate:      20,
	Burst:     0,
	ExpiresIn: 3 * time.Minute,
}

type RateLimiterMiddleware struct {
	core.Middleware
	config RateLimiterConfig
	store  *RateLimiterMemoryStore
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
	if m.config.Burst == 0 {
		m.config.Burst = int(m.config.Rate)
	}

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
		m.Resources.Log.Warn("Rate limit exceeded", "ip", ip)
		return errs.NewErrorTooManyRequests("Rate limit exceeded")
	}

	return next(c)
}
