package limiter_test

import (
	"time"

	"github.com/go-raptor/middlewares/limiter"
	"github.com/go-raptor/raptor/v4"
	"golang.org/x/time/rate"
)

// A strict limiter for the login action: 5 attempts, then one every 12 seconds.
func ExampleNewRateLimiterMiddleware() {
	_ = raptor.Middlewares{
		raptor.Use(limiter.NewRateLimiterMiddleware(limiter.RateLimiterConfig{})),
		raptor.UseOnly(limiter.NewRateLimiterMiddleware(limiter.RateLimiterConfig{
			Rate:  rate.Every(12 * time.Second),
			Burst: 5,
		}), "Auth.Login"),
	}
}
