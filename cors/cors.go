package cors

import (
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
// configures them (via CORSConfig.AllowOrigins or AppConfig["cors_allow_origins"]).
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
		if origin, ok := m.Resources.Config.AppConfig["cors_allow_origins"]; ok {
			m.config.AllowOrigins = []string{origin}
		}
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
			m.Resources.Log.Warn("Invalid origin pattern, skipping", "origin", origin, "error", err)
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

	if m.config.AllowCredentials && m.allowAll {
		m.Resources.Log.Warn("CORS: AllowCredentials with wildcard origin reflects the request origin instead of '*'")
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
			m.Resources.Log.Error("AllowOriginFunc error", "origin", origin, "error", err)
			return ""
		}
		if allowed {
			return origin
		}
		return ""
	}

	if m.allowAll {
		if m.config.AllowCredentials {
			return origin
		}
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
