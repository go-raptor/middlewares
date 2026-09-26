![Raptor](https://static.husak.me/img/raptor/logo.png)

# Raptor middlewares

Middlewares for the [Raptor](https://github.com/go-raptor/raptor) web framework. Each one is its own Go module, so you import only what you use.

| Module | What it does | Install |
| --- | --- | --- |
| [`logger`](#logger) | One structured `slog` line per request | `go get github.com/go-raptor/middlewares/logger` |
| [`cors`](#cors) | CORS headers and preflight handling | `go get github.com/go-raptor/middlewares/cors` |
| [`csrf`](#csrf) | Rejects cross-origin writes using `http.CrossOriginProtection` | `go get github.com/go-raptor/middlewares/csrf` |
| [`limiter`](#limiter) | Token-bucket rate limiting per client IP | `go get github.com/go-raptor/middlewares/limiter` |

```go
func Middlewares() raptor.Middlewares {
	return raptor.Middlewares{
		raptor.Use(&logger.LoggerMiddleware{}),
		raptor.Use(&cors.CORSMiddleware{}),
		raptor.Use(&csrf.CSRFMiddleware{}),
		raptor.Use(limiter.NewRateLimiterMiddleware(limiter.RateLimiterConfig{})),
		raptor.UseOnly(limiter.NewRateLimiterMiddleware(limiter.RateLimiterConfig{
			Rate:  rate.Every(12 * time.Second),
			Burst: 5,
		}), "Auth.Login"),
	}
}
```

## logger

Writes one line per request with the client IP, method, path, status and duration. A successful request is logged at info level with its handler. When the handler returns an error, the line is logged at error level with the error's message.

The attrs of an `errs.Error` often carry request data: a validation issue list holds the submitted values, passwords included. So by default only their keys are logged, as `attr_keys=[email password]`. Choose what gets logged with `LoggerConfig.ErrorAttrs`:

```go
raptor.Use(logger.NewLoggerMiddleware(logger.LoggerConfig{
	ErrorAttrs: func(attrs map[string]any) []slog.Attr {
		return []slog.Attr{slog.Any("constraint", attrs["constraint"])}
	},
}))
```

`logger.ErrorAttrValues` logs every value verbatim, the behavior before v1.1.0. Use it only when no attr ever holds request data.

## cors

Configure allowed origins in code with `CORSConfig.AllowOrigins`, or in config, where `cors_allow_origins` is a comma-separated list:

```yaml
app:
  cors_allow_origins: "https://app.example.com, https://admin.example.com"
  cors_allow_credentials: "true"
```

A value set in `CORSConfig` takes precedence over the config value: config only fills what code leaves unset, so `cors_allow_credentials` can turn credentials on but never turn off `AllowCredentials: true`. It must be exactly `"true"`. If a listed frontend also sends writes and you use [csrf](#csrf), list it in `csrf_trusted_origins` too, or its POST, PUT and DELETE requests get a 403. Patterns such as `https://*.example.com` are supported. `"*"` combined with credentials is refused at startup, because it would let any site make credentialed requests and read the responses.

## csrf

A cookie-authenticated API needs CSRF protection. Three defenses combine:

1. **`SameSite=Lax` cookies.** The browser doesn't attach the cookie to cross-site POST, PUT or DELETE requests. It does attach it to top-level cross-site GET navigations, so GET must never change state.
2. **JSON-only request bodies.** A forged HTML form can't send `application/json`. This only holds if the app rejects writes whose `Content-Type` isn't JSON: Raptor's `ctx.Bind` doesn't check it, so a form posting `text/plain` with a JSON-shaped body would bind. Multipart uploads give this defense up.
3. **This middleware.** It wraps Go's `http.CrossOriginProtection`, which rejects cross-origin unsafe requests based on `Sec-Fetch-Site`, falling back to comparing `Origin` with `Host`. It covers every endpoint, uploads included, and needs no tokens.

Register it globally with `raptor.Use(&csrf.CSRFMiddleware{})`. GET, HEAD and OPTIONS always pass. A rejected request gets `403 {"code":403,"message":"Cross-origin request rejected"}`.

Same-origin deployments configure nothing. For a frontend that genuinely lives on another origin:

```yaml
app:
  csrf_trusted_origins: "https://admin.example.com"
```

Origins are matched exactly: unlike `cors_allow_origins`, wildcards such as `https://*.example.com` aren't supported and fail at startup. A frontend on another origin usually needs listing twice, in `cors_allow_origins` so the browser lets it read responses and in `csrf_trusted_origins` so its writes aren't rejected.

In code, `csrf.NewCSRFMiddleware(csrf.CSRFConfig{TrustedOrigins: ..., BypassPatterns: ...})` does the same. `BypassPatterns` are ServeMux patterns such as `"POST /api/v1/webhooks/{provider}"`, for server-to-server callbacks that authenticate themselves. An invalid pattern panics at startup.

Deployment details:

- **Production.** Serve HTTPS, or preserve the `Host` header at the reverse proxy (`proxy_set_header Host $host;`). Browsers send `Sec-Fetch-Site` only to HTTPS origins and localhost. Without it the check compares `Origin` with `Host`, so a proxy that rewrites `Host` rejects every write. Each rejection is logged at warn level with the request's `origin`, `sec_fetch_site` and `host`, which shows which case you're in.
- **Vite dev proxy.** Proxy the API with the object form and without `changeOrigin`, so `Host` is preserved:

  ```ts
  // vite.config.ts
  server: {
  	proxy: {
  		'/api': { target: 'http://localhost:3000' },
  	},
  },
  ```
- **Tests and non-browser clients** send neither header and pass. Prove the protection is active with `raptor.WithHeader("Sec-Fetch-Site", "cross-site")`.

## limiter

A token bucket per client IP, keyed on `ctx.RealIP()`. Behind a proxy, configure `server.ip_extractor` and `server.trusted_proxies` in Raptor. The zero config allows 20 requests per second with a burst of 20. That suits general API throttling but does nothing against password guessing, so add a strict limiter on the login action:

```go
raptor.UseOnly(limiter.NewRateLimiterMiddleware(limiter.RateLimiterConfig{
	Rate:  rate.Every(12 * time.Second), // 5 per minute sustained
	Burst: 5,
}), "Auth.Login"),
```

Rejected requests get `429` with a `Retry-After` header.

In tests, every request comes from httptest's `192.0.2.1`, so a suite that logs in through the real endpoint more than five times trips the login limiter. Give each test client its own address with `raptor.WithRemoteAddr` (raptor/v4 v4.4.0+).
