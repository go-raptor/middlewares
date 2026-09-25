package csrf

import (
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-raptor/raptor/v4/config"
	"github.com/go-raptor/raptor/v4/core"
)

func testResources(appConfig map[string]string) *core.Resources {
	r := core.NewResources()
	cfg := config.NewConfigDefaults()
	maps.Copy(cfg.AppConfig, appConfig)
	r.SetConfig(cfg)
	r.SetLogHandler(slog.NewTextHandler(io.Discard, nil))
	return r
}

func newMiddleware(t *testing.T, cfg CSRFConfig, appConfig map[string]string) *CSRFMiddleware {
	t.Helper()
	m := NewCSRFMiddleware(cfg)
	m.Init(testResources(appConfig))
	if err := m.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return m
}

// serve runs one request through Handle and renders a returned error the way
// Raptor does. The request's Host is api.example.
func serve(m *CSRFMiddleware, method, path string, headers map[string]string) (*httptest.ResponseRecorder, bool) {
	req := httptest.NewRequest(method, "http://api.example"+path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	ctx := core.NewContext(core.NewCore(testResources(nil)), req, rec)
	called := false
	if err := m.Handle(ctx, func(c *core.Context) error {
		called = true
		return c.NoContent()
	}); err != nil {
		ctx.Error(err)
	}
	return rec, called
}

var crossSite = map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}

func TestSameOriginWritePasses(t *testing.T) {
	m := newMiddleware(t, CSRFConfig{}, nil)
	if _, called := serve(m, http.MethodPost, "/things", map[string]string{"Sec-Fetch-Site": "same-origin"}); !called {
		t.Fatal("a same-origin POST must pass")
	}
}

func TestCrossSiteWriteGetsJSON403(t *testing.T) {
	m := newMiddleware(t, CSRFConfig{}, nil)
	rec, called := serve(m, http.MethodPost, "/things", crossSite)
	if called {
		t.Fatal("a cross-site POST must not reach the handler")
	}
	if rec.Code != http.StatusForbidden || rec.Body.String() != `{"code":403,"message":"Cross-origin request rejected"}` {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestSafeMethodsAlwaysPass(t *testing.T) {
	m := newMiddleware(t, CSRFConfig{}, nil)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if _, called := serve(m, method, "/things", crossSite); !called {
			t.Errorf("cross-site %s must pass", method)
		}
	}
}

func TestTrustedOriginsPass(t *testing.T) {
	fromConfig := newMiddleware(t, CSRFConfig{TrustedOrigins: []string{"https://evil.example"}}, nil)
	if _, called := serve(fromConfig, http.MethodPost, "/things", crossSite); !called {
		t.Error("an origin in CSRFConfig.TrustedOrigins must pass")
	}
	fromApp := newMiddleware(t, CSRFConfig{}, map[string]string{
		"csrf_trusted_origins": "https://admin.example, https://evil.example,, ",
	})
	if _, called := serve(fromApp, http.MethodPost, "/things", crossSite); !called {
		t.Error("an origin in csrf_trusted_origins must pass (entries are trimmed, empties skipped)")
	}
}

func TestInvalidTrustedOriginFailsSetup(t *testing.T) {
	m := NewCSRFMiddleware(CSRFConfig{TrustedOrigins: []string{"https://admin.example/path"}})
	m.Init(testResources(nil))
	if err := m.Setup(); err == nil {
		t.Fatal("an origin with a path must fail Setup")
	}
}

func TestRequestWithoutBrowserHeadersPasses(t *testing.T) {
	m := newMiddleware(t, CSRFConfig{}, nil)
	if _, called := serve(m, http.MethodPost, "/things", nil); !called {
		t.Fatal("a request with neither Sec-Fetch-Site nor Origin (non-browser client, test) must pass")
	}
}

func TestOriginFallbackComparesHost(t *testing.T) {
	m := newMiddleware(t, CSRFConfig{}, nil)
	if _, called := serve(m, http.MethodPost, "/things", map[string]string{"Origin": "http://api.example"}); !called {
		t.Error("without Sec-Fetch-Site, an Origin matching Host must pass")
	}
	if _, called := serve(m, http.MethodPost, "/things", map[string]string{"Origin": "https://evil.example"}); called {
		t.Error("without Sec-Fetch-Site, a foreign Origin must be rejected")
	}
}

func TestBypassPatternPasses(t *testing.T) {
	m := newMiddleware(t, CSRFConfig{BypassPatterns: []string{"POST /webhooks/{provider}"}}, nil)
	if _, called := serve(m, http.MethodPost, "/webhooks/stripe", crossSite); !called {
		t.Error("a bypass pattern must exempt the request")
	}
	if _, called := serve(m, http.MethodPost, "/things", crossSite); called {
		t.Error("the bypass must not cover other paths")
	}
}
