package cors

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

func testResources() *core.Resources {
	r := core.NewResources()
	r.SetConfig(config.NewConfigDefaults())
	r.SetLogHandler(slog.NewTextHandler(io.Discard, nil))
	return r
}

func newMiddleware(t *testing.T, cfg CORSConfig) *CORSMiddleware {
	t.Helper()
	m := NewCORSMiddleware(cfg)
	m.Init(testResources())
	if err := m.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return m
}

// handle drives a request through Handle and reports the recorder plus whether
// the downstream handler ran.
func handle(t *testing.T, m *CORSMiddleware, method, origin string, reqHeaders map[string]string) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	req := httptest.NewRequest(method, "/", nil)
	if origin != "" {
		req.Header.Set(core.HeaderOrigin, origin)
	}
	for k, v := range reqHeaders {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	ctx := core.NewContext(core.NewCore(testResources()), req, rec)

	nextCalled := false
	err := m.Handle(ctx, func(c *core.Context) error {
		nextCalled = true
		return c.Status(http.StatusOK)
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	return rec, nextCalled
}

// --- the critical finding ---

func TestSetupRejectsWildcardWithCredentials(t *testing.T) {
	m := NewCORSMiddleware(CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowCredentials: true,
	})
	m.Init(testResources())

	if err := m.Setup(); err == nil {
		t.Fatal("Setup must reject '*' origin combined with AllowCredentials: reflecting the request origin with credentials lets any site make credentialed cross-origin requests (critical CORS bypass)")
	}
}

func TestSetupRejectsWildcardWithCredentialsFromAppConfig(t *testing.T) {
	r := core.NewResources()
	cfg := config.NewConfigDefaults()
	cfg.AppConfig["cors_allow_origins"] = "*"
	cfg.AppConfig["cors_allow_credentials"] = "true"
	r.SetConfig(cfg)
	r.SetLogHandler(slog.NewTextHandler(io.Discard, nil))

	m := NewCORSMiddleware(CORSConfig{})
	m.Init(r)

	if err := m.Setup(); err == nil {
		t.Fatal("the wildcard+credentials hole must also be rejected when it arrives via AppConfig")
	}
}

func TestMatchOriginNeverReflectsWildcard(t *testing.T) {
	// Simulate the dangerous internal state directly (AllowOrigins: ["*"] +
	// credentials) to prove matchOrigin cannot reflect even if reached.
	m := NewCORSMiddleware(CORSConfig{AllowCredentials: true})
	m.Init(testResources())
	m.allowAll = true

	if got := m.matchOrigin("https://evil.example"); got == "https://evil.example" {
		t.Fatalf("matchOrigin reflected an arbitrary origin for a wildcard policy (got %q); it must return \"*\" and never echo the caller", got)
	}
}

// --- the legitimate credentialed paths must keep working ---

func TestExactOriginWithCredentials(t *testing.T) {
	m := newMiddleware(t, CORSConfig{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowCredentials: true,
	})

	rec, next := handle(t, m, http.MethodGet, "http://localhost:5173", nil)
	if !next {
		t.Fatal("an allowed request should reach the handler")
	}
	if got := rec.Header().Get(core.HeaderAccessControlAllowOrigin); got != "http://localhost:5173" {
		t.Fatalf("Access-Control-Allow-Origin: got %q, want the exact origin", got)
	}
	if got := rec.Header().Get(core.HeaderAccessControlAllowCredentials); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials: got %q, want true", got)
	}
}

func TestFuncApprovedOriginReflectedWithCredentials(t *testing.T) {
	m := newMiddleware(t, CORSConfig{
		AllowCredentials: true,
		AllowOriginFunc: func(o string) (bool, error) {
			return o == "https://app.example", nil
		},
	})

	if got := m.matchOrigin("https://app.example"); got != "https://app.example" {
		t.Fatalf("a func-approved origin must be reflected (the legitimate credentialed path); got %q", got)
	}
	if got := m.matchOrigin("https://evil.example"); got != "" {
		t.Fatalf("a func-rejected origin must not be allowed; got %q", got)
	}
}

// --- wildcard without credentials: public API, literal "*" ---

func TestWildcardWithoutCredentialsReturnsStar(t *testing.T) {
	m := newMiddleware(t, CORSConfig{AllowOrigins: []string{"*"}})

	rec, next := handle(t, m, http.MethodGet, "https://anything.example", nil)
	if !next {
		t.Fatal("a public wildcard request should reach the handler")
	}
	if got := rec.Header().Get(core.HeaderAccessControlAllowOrigin); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin: got %q, want \"*\" (never a reflected origin)", got)
	}
	if got := rec.Header().Get(core.HeaderAccessControlAllowCredentials); got != "" {
		t.Fatalf("credentials header must be absent for a wildcard policy, got %q", got)
	}
}

// --- existing good behavior, locked in ---

func TestDisallowedOriginPassesThroughWithoutCorsHeaders(t *testing.T) {
	m := newMiddleware(t, CORSConfig{AllowOrigins: []string{"https://app.example"}})

	rec, next := handle(t, m, http.MethodGet, "https://evil.example", nil)
	if !next {
		t.Fatal("CORS does not block the request itself; the handler still runs (the browser blocks reading the response)")
	}
	if got := rec.Header().Get(core.HeaderAccessControlAllowOrigin); got != "" {
		t.Fatalf("a disallowed origin must receive no Access-Control-Allow-Origin, got %q", got)
	}
}

func TestPreflightAllowedOrigin(t *testing.T) {
	m := newMiddleware(t, CORSConfig{AllowOrigins: []string{"https://app.example"}})

	rec, next := handle(t, m, http.MethodOptions, "https://app.example", map[string]string{
		core.HeaderAccessControlRequestMethod: "POST",
	})
	if next {
		t.Fatal("a preflight request must terminate in the middleware, not reach the handler")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status: got %d, want 204", rec.Code)
	}
	if got := rec.Header().Get(core.HeaderAccessControlAllowMethods); got == "" {
		t.Fatal("preflight must advertise Access-Control-Allow-Methods")
	}
}

func TestVaryOriginAlwaysSet(t *testing.T) {
	m := newMiddleware(t, CORSConfig{AllowOrigins: []string{"https://app.example"}})

	rec, _ := handle(t, m, http.MethodGet, "", nil) // no Origin header at all
	if got := rec.Header().Get(core.HeaderVary); got != "Origin" {
		t.Fatalf("Vary: Origin must be set so caches don't serve a CORS response to the wrong origin; got %q", got)
	}
}

func TestAppConfigOriginsAreCommaSeparated(t *testing.T) {
	r := testResources()
	r.Config.AppConfig["cors_allow_origins"] = "https://a.example, https://b.example,, "
	m := NewCORSMiddleware(CORSConfig{})
	m.Init(r)
	if err := m.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	for _, origin := range []string{"https://a.example", "https://b.example"} {
		rec, _ := handle(t, m, http.MethodGet, origin, nil)
		if got := rec.Header().Get(core.HeaderAccessControlAllowOrigin); got != origin {
			t.Errorf("origin %s: Access-Control-Allow-Origin = %q", origin, got)
		}
	}
}

// credentialsFor reports the Access-Control-Allow-Credentials an allowed origin gets from a
// middleware configured in code by cfg and in app config by app.
func credentialsFor(t *testing.T, cfg CORSConfig, app map[string]string) string {
	t.Helper()
	r := testResources()
	maps.Copy(r.Config.AppConfig, app)
	cfg.AllowOrigins = []string{"http://localhost:5173"}
	m := NewCORSMiddleware(cfg)
	m.Init(r)
	if err := m.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	rec, _ := handle(t, m, http.MethodGet, "http://localhost:5173", nil)
	return rec.Header().Get(core.HeaderAccessControlAllowCredentials)
}

// A value set in code wins, as AllowOrigins does over cors_allow_origins: app config only fills
// what code leaves unset, so it can turn credentials on but never off.
func TestCodeCredentialsWinOverAppConfig(t *testing.T) {
	if got := credentialsFor(t, CORSConfig{AllowCredentials: true}, map[string]string{"cors_allow_credentials": "false"}); got != "true" {
		t.Fatalf("cors_allow_credentials \"false\" overrode AllowCredentials set in code: got %q", got)
	}
}

func TestAppConfigEnablesCredentials(t *testing.T) {
	if got := credentialsFor(t, CORSConfig{}, map[string]string{"cors_allow_credentials": "true"}); got != "true" {
		t.Fatalf("cors_allow_credentials \"true\" did not enable credentials: got %q", got)
	}
}

// A preflight is an OPTIONS request with Origin and
// Access-Control-Request-Method. Any other OPTIONS belongs to the app, whose
// own OPTIONS routes, 404 and 405 must still answer it.
func TestOptionsWithoutPreflightHeadersReachesHandler(t *testing.T) {
	m := newMiddleware(t, CORSConfig{AllowOrigins: []string{"https://app.example"}})

	if _, next := handle(t, m, http.MethodOptions, "", nil); !next {
		t.Fatal("OPTIONS without Origin is not a preflight and must reach the app")
	}
	rec, next := handle(t, m, http.MethodOptions, "https://app.example", nil)
	if !next {
		t.Fatal("OPTIONS without Access-Control-Request-Method is not a preflight and must reach the app")
	}
	if got := rec.Header().Get(core.HeaderAccessControlAllowOrigin); got != "https://app.example" {
		t.Fatalf("it is still a cross-origin request and gets Access-Control-Allow-Origin, got %q", got)
	}
}

func TestOriginPatternsMatchWholeLabelsAndPorts(t *testing.T) {
	m := newMiddleware(t, CORSConfig{AllowOrigins: []string{"https://*.example.com", "http://localhost:*", "http://[::1]:*"}})

	for origin, want := range map[string]bool{
		"https://app.example.com":          true,
		"https://a.b.example.com":          true,
		"http://localhost:5173":            true,
		"http://[::1]:3000":                true,
		"https://example.com":              false,
		"https://attackerexample.com":      false,
		"https://app.example.com.evil.com": false,
		"https://app.example.com:8443":     false,
		"http://localhost":                 false,
		"http://localhost:abc":             false,
		"http://localhost.evil.com:80":     false,
	} {
		if got := m.matchOrigin(origin) != ""; got != want {
			t.Errorf("%s: allowed=%v, want %v", origin, got, want)
		}
	}
}

func TestSetupRejectsLoosePatternsAndNull(t *testing.T) {
	for _, origin := range []string{"https://*example.com", "https://ex*.com", "https://app.*.com", "https://*.", "https://?.example.com", "http://localhost:30*", "*://example.com", "null"} {
		m := NewCORSMiddleware(CORSConfig{AllowOrigins: []string{origin}})
		m.Init(testResources())
		if err := m.Setup(); err == nil {
			t.Errorf("%q must fail Setup", origin)
		}
	}
}
