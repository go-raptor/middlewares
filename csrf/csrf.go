// Package csrf rejects cross-origin state-changing requests with Go's
// http.CrossOriginProtection, which reads Sec-Fetch-Site and falls back to
// comparing Origin with Host. No tokens are involved.
package csrf

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-raptor/raptor/v4"
	"github.com/go-raptor/raptor/v4/errs"
)

type CSRFConfig struct {
	// TrustedOrigins may make cross-origin writes, e.g.
	// "https://admin.example.com". When empty, AppConfig["csrf_trusted_origins"]
	// (comma-separated) is used instead. Origins are matched exactly; unlike
	// cors_allow_origins, wildcards are not supported and fail Setup.
	TrustedOrigins []string `yaml:"trusted_origins"`

	// BypassPatterns are ServeMux patterns exempt from the check, e.g.
	// "POST /api/v1/webhooks/{provider}" for server-to-server callbacks that
	// authenticate themselves. An invalid pattern panics at startup.
	BypassPatterns []string `yaml:"bypass_patterns"`
}

// rejectionLogInterval spaces the diagnostic lines for rejected requests.
// The first rejection is logged at once and later ones at most once per
// interval, with a count of those skipped, so a flood of forged requests
// can't flood the log. The logger middleware still records each 403.
const rejectionLogInterval = 10 * time.Second

type CSRFMiddleware struct {
	raptor.Middleware

	config     CSRFConfig
	protection *http.CrossOriginProtection

	logMu      sync.Mutex
	nextLog    time.Time
	suppressed int
	now        func() time.Time
}

func NewCSRFMiddleware(config CSRFConfig) *CSRFMiddleware {
	return &CSRFMiddleware{config: config}
}

func (m *CSRFMiddleware) Setup() error {
	if m.now == nil {
		m.now = time.Now
	}
	m.protection = http.NewCrossOriginProtection()

	origins := m.config.TrustedOrigins
	if len(origins) == 0 {
		origins = splitList(m.Config.AppConfig["csrf_trusted_origins"])
	}
	for _, origin := range origins {
		if strings.Contains(origin, "*") {
			return fmt.Errorf("csrf: trusted origin %q: wildcards are not supported, list each origin", origin)
		}
		if err := m.protection.AddTrustedOrigin(origin); err != nil {
			return fmt.Errorf("csrf: %w", err)
		}
	}
	for _, pattern := range m.config.BypassPatterns {
		m.protection.AddInsecureBypassPattern(pattern)
	}
	return nil
}

func (m *CSRFMiddleware) Handle(ctx *raptor.Context, next func(*raptor.Context) error) error {
	req := ctx.Request()
	if err := m.protection.Check(req); err != nil {
		// Origin, Sec-Fetch-Site and Host are what tell a real cross-site
		// request apart from a proxy that rewrites Host.
		if suppressed, ok := m.logRejection(); ok {
			m.Log.Warn("Rejected cross-origin request",
				"ip", ctx.RealIP(), "method", req.Method, "path", req.URL.Path,
				"origin", req.Header.Get("Origin"), "sec_fetch_site", req.Header.Get("Sec-Fetch-Site"),
				"host", req.Host, "reason", err, "suppressed", suppressed)
		}
		return errs.NewErrorForbidden("Cross-origin request rejected")
	}
	return next(ctx)
}

// logRejection reports whether this rejection gets a diagnostic line, and
// how many rejections went unlogged since the previous one.
func (m *CSRFMiddleware) logRejection() (suppressed int, ok bool) {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	now := m.now()
	if now.Before(m.nextLog) {
		m.suppressed++
		return 0, false
	}
	suppressed, m.suppressed = m.suppressed, 0
	m.nextLog = now.Add(rejectionLogInterval)
	return suppressed, true
}

// splitList reads a comma-separated config value, trimming spaces and
// dropping empty entries.
func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
