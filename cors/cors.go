package cors

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/go-raptor/raptor/v4/core"
)

type CORSConfig struct {
	AllowOrigins     []string                          `yaml:"allow_origins"`
	AllowOriginFunc  func(origin string) (bool, error) `yaml:"-"`
	AllowMethods     []string                          `yaml:"allow_methods"`
	AllowHeaders     []string                          `yaml:"allow_headers"`
	AllowCredentials bool                              `yaml:"allow_credentials"`
	ExposeHeaders    []string                          `yaml:"expose_headers"`
	MaxAge           int                               `yaml:"max_age"`
}

// DefaultCORSConfig is safe-by-default: no origins are allowed until the user
// configures them (via CORSConfig.AllowOrigins or AppConfig["cors_allow_origins"],
// a comma-separated list).
// AllowCredentials defaults to false and must be opted into explicitly.
// MaxAge: 0 applies the 3600s default; set MaxAge to -1 to omit the header.
var DefaultCORSConfig = CORSConfig{
	AllowMethods:     []string{"GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"},
	AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
	AllowCredentials: false,
	MaxAge:           3600,
}

type CORSMiddleware struct {
	core.Middleware
	config           CORSConfig
	allowAll         bool
	exactOrigins     map[string]struct{}
	wildcardPatterns []*regexp.Regexp
	allowMethods     string
	allowHeaders     string
	exposeHeaders    string
	maxAge           string
}

func NewCORSMiddleware(config CORSConfig) *CORSMiddleware {
	return &CORSMiddleware{config: config}
}

func (m *CORSMiddleware) Setup() error {
	if len(m.config.AllowOrigins) == 0 {
		m.config.AllowOrigins = splitList(m.Config.AppConfig["cors_allow_origins"])
	}
	if len(m.config.AllowMethods) == 0 {
		m.config.AllowMethods = DefaultCORSConfig.AllowMethods
	}
	if len(m.config.AllowHeaders) == 0 {
		m.config.AllowHeaders = DefaultCORSConfig.AllowHeaders
	}
	if m.config.MaxAge == 0 {
		m.config.MaxAge = DefaultCORSConfig.MaxAge
	}
	// Like the origins, code wins: config only fills what code left unset, so it can turn
	// credentials on but never off.
	if !m.config.AllowCredentials {
		m.config.AllowCredentials = m.Config.AppConfig["cors_allow_credentials"] == "true"
	}

	m.allowAll = slices.Contains(m.config.AllowOrigins, "*")

	m.exactOrigins = make(map[string]struct{}, len(m.config.AllowOrigins))
	for _, origin := range m.config.AllowOrigins {
		if origin == "*" {
			continue
		}
		if !strings.ContainsAny(origin, "*?") {
			m.exactOrigins[origin] = struct{}{}
			continue
		}
		pattern := "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(origin), "\\*", ".*"), "\\?", ".") + "$"
		re, err := regexp.Compile(pattern)
		if err != nil {
			m.Log.Warn("Invalid origin pattern, skipping", "origin", origin, "error", err)
			continue
		}
		m.wildcardPatterns = append(m.wildcardPatterns, re)
	}

	m.allowMethods = strings.Join(m.config.AllowMethods, ",")
	m.allowHeaders = strings.Join(m.config.AllowHeaders, ",")
	m.exposeHeaders = strings.Join(m.config.ExposeHeaders, ",")
	if m.config.MaxAge > 0 {
		m.maxAge = strconv.Itoa(m.config.MaxAge)
	}

	// A wildcard origin with credentials is invalid: browsers reject a literal
	// "*" alongside Access-Control-Allow-Credentials, and the only way to make
	// it "work" is to reflect the request origin — which lets any site issue
	// credentialed cross-origin requests and read the responses. Refuse it at
	// startup and require an explicit origin list. A custom AllowOriginFunc is
	// exempt: it decides origins itself, so the wildcard list is never consulted.
	if m.config.AllowCredentials && m.allowAll && m.config.AllowOriginFunc == nil {
		return fmt.Errorf(`cors: AllowCredentials cannot be combined with a wildcard "*" origin; list explicit origins instead`)
	}

	return nil
}

func (m *CORSMiddleware) Handle(c *core.Context, next func(*core.Context) error) error {
	req := c.Request()
	res := c.Response()
	origin := req.Header.Get(core.HeaderOrigin)
	preflight := req.Method == "OPTIONS"

	addVary(res.Header(), core.HeaderOrigin)

	if origin == "" {
		if preflight {
			return c.NoContent()
		}
		return next(c)
	}

	allowOrigin := m.matchOrigin(origin)
	if allowOrigin == "" {
		if preflight {
			return c.NoContent()
		}
		return next(c)
	}

	res.Header().Set(core.HeaderAccessControlAllowOrigin, allowOrigin)
	if m.config.AllowCredentials {
		res.Header().Set(core.HeaderAccessControlAllowCredentials, "true")
	}

	if !preflight {
		if m.exposeHeaders != "" {
			res.Header().Set(core.HeaderAccessControlExposeHeaders, m.exposeHeaders)
		}
		return next(c)
	}

	addVary(res.Header(), core.HeaderAccessControlRequestMethod)
	addVary(res.Header(), core.HeaderAccessControlRequestHeaders)
	res.Header().Set(core.HeaderAccessControlAllowMethods, m.allowMethods)

	if m.allowHeaders != "" {
		res.Header().Set(core.HeaderAccessControlAllowHeaders, m.allowHeaders)
	} else if h := req.Header.Get(core.HeaderAccessControlRequestHeaders); h != "" {
		res.Header().Set(core.HeaderAccessControlAllowHeaders, h)
	}

	if m.maxAge != "" {
		res.Header().Set(core.HeaderAccessControlMaxAge, m.maxAge)
	}

	return c.NoContent()
}

func (m *CORSMiddleware) matchOrigin(origin string) string {
	if m.config.AllowOriginFunc != nil {
		allowed, err := m.config.AllowOriginFunc(origin)
		if err != nil {
			m.Log.Error("AllowOriginFunc error", "origin", origin, "error", err)
			return ""
		}
		if allowed {
			return origin
		}
		return ""
	}

	if m.allowAll {
		// Never reflect an arbitrary origin for a wildcard policy. Wildcard +
		// credentials is refused at Setup, so credentials are off here and the
		// literal "*" is the correct, safe response.
		return "*"
	}

	if _, ok := m.exactOrigins[origin]; ok {
		return origin
	}

	for _, re := range m.wildcardPatterns {
		if re.MatchString(origin) {
			return origin
		}
	}

	return ""
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

func addVary(h http.Header, token string) {
	for _, v := range h.Values(core.HeaderVary) {
		for len(v) > 0 {
			var part string
			if i := strings.IndexByte(v, ','); i >= 0 {
				part, v = v[:i], v[i+1:]
			} else {
				part, v = v, ""
			}
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return
			}
		}
	}
	h.Add(core.HeaderVary, token)
}
