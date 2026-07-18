package limiter

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-raptor/raptor/v4/config"
	"github.com/go-raptor/raptor/v4/core"
	"github.com/go-raptor/raptor/v4/errs"
)

func testResources() *core.Resources {
	r := core.NewResources()
	r.SetConfig(config.NewConfigDefaults())
	r.SetLogHandler(slog.NewTextHandler(io.Discard, nil))
	return r
}

func handle(t *testing.T, m *RateLimiterMiddleware) (*httptest.ResponseRecorder, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil) // RemoteAddr defaults to 192.0.2.1:1234
	rec := httptest.NewRecorder()
	ctx := core.NewContext(core.NewCore(testResources()), req, rec)
	err := m.Handle(ctx, func(c *core.Context) error {
		return c.Status(http.StatusOK)
	})
	return rec, err
}

func TestBurstFloorForFractionalRate(t *testing.T) {
	m := NewRateLimiterMiddleware(RateLimiterConfig{Rate: 0.5})
	m.Init(testResources())

	if m.config.Burst < 1 {
		t.Fatalf("a fractional rate must still yield burst >= 1, else every request is denied; got %d", m.config.Burst)
	}
	if _, err := handle(t, m); err != nil {
		t.Fatalf("the first request under a fractional rate should be allowed, got %v", err)
	}
}

func TestHandleAllowsThenRejectsWithRetryAfter(t *testing.T) {
	m := NewRateLimiterMiddleware(RateLimiterConfig{Rate: 1, Burst: 1})
	m.Init(testResources())

	if _, err := handle(t, m); err != nil {
		t.Fatalf("first request should pass, got %v", err)
	}

	rec, err := handle(t, m)
	var apiErr *errs.Error
	if !errors.As(err, &apiErr) || apiErr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request should be rejected with 429, got %v", err)
	}
	if rec.Header().Get(core.HeaderRetryAfter) == "" {
		t.Fatal("a 429 response must carry a Retry-After header so clients can back off")
	}
}

func TestDefaultsApplied(t *testing.T) {
	m := NewRateLimiterMiddleware(RateLimiterConfig{})
	m.Init(testResources())

	if m.config.Rate != DefaultRateLimiterConfig.Rate {
		t.Errorf("Rate default: got %v", m.config.Rate)
	}
	if m.config.ExpiresIn != DefaultRateLimiterConfig.ExpiresIn {
		t.Errorf("ExpiresIn default: got %v", m.config.ExpiresIn)
	}
	if m.config.MaxVisitors != DefaultRateLimiterConfig.MaxVisitors {
		t.Errorf("MaxVisitors default: got %v", m.config.MaxVisitors)
	}
	if m.config.Burst != int(DefaultRateLimiterConfig.Rate) {
		t.Errorf("Burst should default to the rate, got %d", m.config.Burst)
	}
}
