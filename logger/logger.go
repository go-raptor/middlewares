package logger

import (
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/go-raptor/raptor/v4"
	"github.com/go-raptor/raptor/v4/core"
	"github.com/go-raptor/raptor/v4/errs"
)

type LoggerMiddleware struct {
	raptor.Middleware
}

func (m *LoggerMiddleware) Setup() error {
	return nil
}

func (m *LoggerMiddleware) Handle(c *raptor.Context, next func(*raptor.Context) error) error {
	startTime := time.Now()
	err := next(c)
	m.logRequest(c, startTime, err)
	return err
}

func (m *LoggerMiddleware) logRequest(ctx *raptor.Context, startTime time.Time, err error) {
	attrs := []slog.Attr{
		slog.String("ip", ctx.RealIP()),
		slog.String("method", ctx.Request().Method),
		slog.String("path", ctx.Request().URL.Path),
		slog.Int("status", ctx.Response().Status),
		slog.String("duration", formatDuration(time.Since(startTime))),
	}

	// Pass the request's context so a context-aware handler keeps trace or
	// correlation values instead of losing them to context.Background().
	reqCtx := ctx.Request().Context()

	if err == nil {
		attrs = append(attrs, slog.String("handler", core.ActionDescriptor(ctx.Controller(), ctx.Action())))
		m.Log.LogAttrs(reqCtx, slog.LevelInfo, "Request processed", attrs...)
		return
	}

	// errors.As, not a bare type assertion, so a wrapped *errs.Error still
	// contributes its message and attrs to the log line.
	var raptorErr *errs.Error
	if errors.As(err, &raptorErr) {
		attrs = append(attrs, slog.String("message", raptorErr.Message))
		attrs = appendErrorAttrs(attrs, raptorErr.Attrs)
	}
	m.Log.LogAttrs(reqCtx, slog.LevelError, "Error while processing request", attrs...)
}

func formatDuration(d time.Duration) string {
	switch {
	case d < time.Microsecond:
		return strconv.FormatInt(d.Nanoseconds(), 10) + "ns"
	case d < time.Millisecond:
		return strconv.FormatInt(d.Microseconds(), 10) + "µs"
	case d < time.Second:
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	default:
		return strconv.FormatFloat(d.Seconds(), 'f', 2, 64) + "s"
	}
}

func appendErrorAttrs(attrs []slog.Attr, errAttrs map[string]any) []slog.Attr {
	for key, value := range errAttrs {
		if !containsKey(attrs, key) {
			attrs = append(attrs, slog.Any(key, value))
		}
	}
	return attrs
}

func containsKey(attrs []slog.Attr, key string) bool {
	for _, a := range attrs {
		if a.Key == key {
			return true
		}
	}
	return false
}
