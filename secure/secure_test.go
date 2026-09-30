package secure

import (
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-raptor/raptor/v4/config"
	"github.com/go-raptor/raptor/v4/core"
	"github.com/go-raptor/raptor/v4/errs"
)

func testResources(appConfig map[string]string) *core.Resources {
	r := core.NewResources()
	cfg := config.NewConfigDefaults()
	maps.Copy(cfg.AppConfig, appConfig)
	r.SetConfig(cfg)
	r.SetLogHandler(slog.NewTextHandler(io.Discard, nil))
	return r
}

func newMiddleware(t *testing.T, cfg SecureConfig, appConfig map[string]string) *SecureMiddleware {
	t.Helper()
	m := NewSecureMiddleware(cfg)
	m.Init(testResources(appConfig))
	if err := m.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return m
}

// serve runs one request through Handle and renders a returned error the
// way Raptor does.
func serve(m *SecureMiddleware, next func(*core.Context) error) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ctx := core.NewContext(core.NewCore(testResources(nil)), httptest.NewRequest(http.MethodGet, "/", nil), rec)
	if err := m.Handle(ctx, next); err != nil {
		ctx.Error(err)
	}
	return rec
}

func noContent(c *core.Context) error { return c.NoContent() }

var wantDefaults = map[string]string{
	"X-Content-Type-Options":     "nosniff",
	"Referrer-Policy":            "strict-origin-when-cross-origin",
	"X-Frame-Options":            "DENY",
	"Content-Security-Policy":    "frame-ancestors 'none'",
	"Cross-Origin-Opener-Policy": "same-origin",
}

func assertDefaults(t *testing.T, h http.Header) {
	t.Helper()
	for name, want := range wantDefaults {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestDefaultHeaders(t *testing.T) {
	rec := serve(newMiddleware(t, SecureConfig{}, nil), noContent)
	assertDefaults(t, rec.Header())
	if v := rec.Header().Get("Strict-Transport-Security"); v != "" {
		t.Fatalf("HSTS must be opt-in, got %q", v)
	}
}

func TestZeroValueMiddleware(t *testing.T) {
	m := &SecureMiddleware{}
	m.Init(testResources(nil))
	if err := m.Setup(); err != nil {
		t.Fatal(err)
	}
	assertDefaults(t, serve(m, noContent).Header())
}

// Raptor's error rendering drops success-path headers; these must survive.
func TestHeadersSurviveErrorResponses(t *testing.T) {
	rec := serve(newMiddleware(t, SecureConfig{}, nil), func(*core.Context) error {
		return errs.NewErrorNotFound("missing")
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d", rec.Code)
	}
	assertDefaults(t, rec.Header())
}

func TestHSTS(t *testing.T) {
	rec := serve(newMiddleware(t, SecureConfig{HSTSMaxAge: 31536000}, nil), noContent)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("HSTS = %q", got)
	}
	rec = serve(newMiddleware(t, SecureConfig{HSTSMaxAge: 31536000, HSTSIncludeSubdomains: true}, nil), noContent)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS with subdomains = %q", got)
	}
}

func TestHSTSFromAppConfig(t *testing.T) {
	rec := serve(newMiddleware(t, SecureConfig{}, map[string]string{"secure_hsts_max_age": "600"}), noContent)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=600" {
		t.Errorf("HSTS from app config = %q", got)
	}
	m := NewSecureMiddleware(SecureConfig{})
	m.Init(testResources(map[string]string{"secure_hsts_max_age": "a year"}))
	if err := m.Setup(); err == nil {
		t.Fatal("a malformed secure_hsts_max_age must fail Setup")
	}
}

func TestHeaderOverrides(t *testing.T) {
	m := newMiddleware(t, SecureConfig{Headers: map[string]string{
		"x-frame-options":         "",
		"Content-Security-Policy": "default-src 'self'",
	}}, nil)
	rec := serve(m, noContent)
	if v := rec.Header().Get("X-Frame-Options"); v != "" {
		t.Errorf("an empty override must omit the header, got %q", v)
	}
	if v := rec.Header().Get("Content-Security-Policy"); v != "default-src 'self'" {
		t.Errorf("CSP override = %q", v)
	}
}

// Headers are set before next, so a handler can still replace one.
func TestHandlerCanOverride(t *testing.T) {
	rec := serve(newMiddleware(t, SecureConfig{}, nil), func(c *core.Context) error {
		c.Response().Header().Set("Content-Security-Policy", "default-src 'none'")
		return c.NoContent()
	})
	if v := rec.Header().Get("Content-Security-Policy"); v != "default-src 'none'" {
		t.Fatalf("handler's CSP was overwritten: %q", v)
	}
}
