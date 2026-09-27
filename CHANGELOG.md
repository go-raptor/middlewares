# Changelog

Each middleware is its own module, versioned by its own tag (`logger/vX.Y.Z`).

## logger — v1.2.0 (2026-09-27)

### Changed

- **Behavior:** a request line's level now follows the response status instead of whether the handler returned an error: 5xx at error, 4xx at warn, anything else at info. Returned client errors (a 400, a CSRF 403, a 404, a 429 from the rate limiter) drop from error to warn, which leaves error level to server failures, 502 and 504 from failed upstream calls included. A 4xx or 5xx written without returning an error, such as `c.NotFound()`, rises from info. Messages and attributes are unchanged, so queries on the message keep working, but an alert on error level now fires only for 5xx.

### Added

- `LoggerConfig.Level func(status int) slog.Level` picks the level from the status. nil means `StatusLevel`, the new default.

### Performance

- A request line below the configured log level returns before building its attributes: about 45 ns and no allocations, down from about 280 ns and 3 allocations.

## cors — v1.1.0 (2026-09-26)

### Changed

- **Behavior:** `cors_allow_credentials` in app config no longer overrides `AllowCredentials: true` set in code. Like `cors_allow_origins`, config only fills what code leaves unset, so it can turn credentials on but not off. This matches `csrf` and `controllers/spa`.

## csrf — v1.0.0 (2026-09-25)

### Added

- New module wrapping `http.CrossOriginProtection`: rejects cross-origin unsafe requests app-wide with a JSON 403. Trusted origins come from `CSRFConfig.TrustedOrigins` or the comma-separated `csrf_trusted_origins` app config; `BypassPatterns` exempt self-authenticating callbacks. Wildcard origins fail `Setup` (they would never match). Each rejection is logged with the request's Origin, Sec-Fetch-Site and Host.

## logger — v1.1.0 (2026-09-25)

### Changed

- **Behavior:** the attrs of a returned `errs.Error` are no longer logged verbatim, because they often carry request data (passwords included). By default the line lists only their keys, as `attr_keys=[...]`.

### Added

- `LoggerConfig` with `ErrorAttrs func(map[string]any) []slog.Attr`, and `NewLoggerMiddleware(config)`. `&logger.LoggerMiddleware{}` keeps working with the default.
- `ErrorAttrKeys` (the default) and `ErrorAttrValues` (the previous verbatim behavior).

## cors — v1.0.11 (2026-09-25)

### Fixed

- `cors_allow_origins` from app config is split on commas and trimmed; previously the whole value was treated as a single origin.

## limiter — v1.0.3 (2026-09-25)

### Docs

- A login configuration (`Rate: rate.Every(12*time.Second), Burst: 5` scoped with `UseOnly(..., "Auth.Login")`), as a compiled example and in the README. The `DefaultRateLimiterConfig` comment explains that the default does not protect against password guessing.
