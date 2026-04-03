package cors

import (
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

var DefaultCORSConfig = CORSConfig{
	AllowOrigins: []string{"*"},
	AllowMethods: []string{"GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"},
}

type CORSMiddleware struct {
	core.Middleware
	config         CORSConfig
	allowAll       bool
	originPatterns []*regexp.Regexp
	allowMethods   string
	allowHeaders   string
	exposeHeaders  string
	maxAge         string
}

func NewCORSMiddleware(config CORSConfig) *CORSMiddleware {
	return &CORSMiddleware{config: config}
}

func (m *CORSMiddleware) Setup() error {
	if len(m.config.AllowOrigins) == 0 {
		if origin, ok := m.Resources.Config.AppConfig["cors_allow_origins"]; ok {
			m.config.AllowOrigins = []string{origin}
		} else {
			m.config.AllowOrigins = DefaultCORSConfig.AllowOrigins
		}
	}
	if len(m.config.AllowMethods) == 0 {
		m.config.AllowMethods = DefaultCORSConfig.AllowMethods
	}

	m.allowAll = slices.Contains(m.config.AllowOrigins, "*")

	m.originPatterns = make([]*regexp.Regexp, 0, len(m.config.AllowOrigins))
	for _, origin := range m.config.AllowOrigins {
		if origin == "*" {
			continue
		}
		pattern := "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(origin), "\\*", ".*"), "\\?", ".") + "$"
		re, err := regexp.Compile(pattern)
		if err != nil {
			m.Resources.Log.Warn("Invalid origin pattern, skipping", "origin", origin, "error", err)
			continue
		}
		m.originPatterns = append(m.originPatterns, re)
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

	res.Header().Add(core.HeaderVary, core.HeaderOrigin)

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

	res.Header().Add(core.HeaderVary, core.HeaderAccessControlRequestMethod)
	res.Header().Add(core.HeaderVary, core.HeaderAccessControlRequestHeaders)
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

	for _, re := range m.originPatterns {
		if re.MatchString(origin) {
			return origin
		}
	}

	return ""
}
