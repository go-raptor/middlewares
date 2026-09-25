# Changelog

Each middleware is its own module, versioned by its own tag (`logger/vX.Y.Z`).

## csrf — Unreleased (v1.0.0)

### Added

- New module wrapping `http.CrossOriginProtection`: rejects cross-origin unsafe requests app-wide with a JSON 403. Trusted origins come from `CSRFConfig.TrustedOrigins` or the comma-separated `csrf_trusted_origins` app config; `BypassPatterns` exempt self-authenticating callbacks. Wildcard origins fail `Setup` (they would never match). Each rejection is logged with the request's Origin, Sec-Fetch-Site and Host.

## logger — Unreleased (v1.1.0)

### Changed

- **Behavior:** the attrs of a returned `errs.Error` are no longer logged verbatim, because they often carry request data (passwords included). By default the line lists only their keys, as `attr_keys=[...]`.

### Added

- `LoggerConfig` with `ErrorAttrs func(map[string]any) []slog.Attr`, and `NewLoggerMiddleware(config)`. `&logger.LoggerMiddleware{}` keeps working with the default.
- `ErrorAttrKeys` (the default) and `ErrorAttrValues` (the previous verbatim behavior).

## cors — Unreleased (v1.0.11)

### Fixed

- `cors_allow_origins` from app config is split on commas and trimmed; previously the whole value was treated as a single origin.

## limiter — Unreleased (v1.0.3)

### Docs

- A login configuration (`Rate: rate.Every(12*time.Second), Burst: 5` scoped with `UseOnly(..., "Auth.Login")`), as a compiled example and in the README. The `DefaultRateLimiterConfig` comment explains that the default does not protect against password guessing.
