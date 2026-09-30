// Package secure sets browser security headers on every response: no MIME
// sniffing, a conservative referrer policy, no framing, and an isolated
// browsing context. HSTS is opt-in, because it pins browsers to HTTPS for
// as long as its max-age says.
package secure

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"

	"github.com/go-raptor/raptor/v4"
)

// SecureConfig tunes the headers. The zero value sends the defaults without
// HSTS.
type SecureConfig struct {
	// HSTSMaxAge enables Strict-Transport-Security, in seconds, when > 0.
	// When 0, app config secure_hsts_max_age is used; still 0 leaves HSTS
	// off.
	HSTSMaxAge int `yaml:"hsts_max_age"`
	// HSTSIncludeSubdomains extends HSTS to every subdomain.
	HSTSIncludeSubdomains bool `yaml:"hsts_include_subdomains"`
	// Headers overrides the defaults by name: a value replaces the default,
	// "" omits the header.
	Headers map[string]string `yaml:"headers"`
}

// defaultHeaders suit a JSON API and a single-page app served from the same
// origin. The CSP only forbids framing; a full policy depends on the app.
var defaultHeaders = map[string]string{
	"X-Content-Type-Options":     "nosniff",
	"Referrer-Policy":            "strict-origin-when-cross-origin",
	"X-Frame-Options":            "DENY",
	"Content-Security-Policy":    "frame-ancestors 'none'",
	"Cross-Origin-Opener-Policy": "same-origin",
}

type header struct {
	name, value string
}

type SecureMiddleware struct {
	raptor.Middleware

	config  SecureConfig
	headers []header
}

func NewSecureMiddleware(config SecureConfig) *SecureMiddleware {
	return &SecureMiddleware{config: config}
}

// Setup resolves the header set once, so Handle only copies it.
func (m *SecureMiddleware) Setup() error {
	values := maps.Clone(defaultHeaders)
	for name, value := range m.config.Headers {
		values[http.CanonicalHeaderKey(name)] = value
	}

	maxAge := m.config.HSTSMaxAge
	if maxAge == 0 {
		if raw := m.Config.AppConfig["secure_hsts_max_age"]; raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 {
				return fmt.Errorf("secure: app config secure_hsts_max_age %q: want a number of seconds", raw)
			}
			maxAge = n
		}
	}
	if maxAge > 0 {
		hsts := "max-age=" + strconv.Itoa(maxAge)
		if m.config.HSTSIncludeSubdomains {
			hsts += "; includeSubDomains"
		}
		values["Strict-Transport-Security"] = hsts
	}

	m.headers = m.headers[:0]
	for _, name := range slices.Sorted(maps.Keys(values)) {
		if values[name] != "" {
			m.headers = append(m.headers, header{name, values[name]})
		}
	}
	return nil
}

// Handle sets the headers before the handler runs, so they reach error
// responses too and a handler can still replace one, such as a page's own
// Content-Security-Policy.
func (m *SecureMiddleware) Handle(ctx *raptor.Context, next func(*raptor.Context) error) error {
	h := ctx.Response().Header()
	for _, hd := range m.headers {
		h.Set(hd.name, hd.value)
	}
	return next(ctx)
}
