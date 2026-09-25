package logger

import (
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/go-raptor/raptor/v4"
	"github.com/go-raptor/raptor/v4/core"
	"github.com/go-raptor/raptor/v4/errs"
)

// LoggerConfig configures LoggerMiddleware. The zero value is ready to use.
type LoggerConfig struct {
	// ErrorAttrs turns a returned errs.Error's attrs into log attributes.
	// Attrs often carry request data (a validation issue list holds the
	// submitted values, passwords included), so nil means ErrorAttrKeys:
	// only the keys are logged. ErrorAttrValues restores verbatim logging.
	ErrorAttrs func(map[string]any) []slog.Attr `yaml:"-"`
}

type LoggerMiddleware struct {
	raptor.Middleware
	config LoggerConfig
}

func NewLoggerMiddleware(config LoggerConfig) *LoggerMiddleware {
	return &LoggerMiddleware{config: config}
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
		attrs = appendErrorAttrs(attrs, m.errorAttrs(raptorErr.Attrs))
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

// ErrorAttrKeys records which attrs an error carried, without their values,
// as one "attr_keys" attribute holding the sorted keys.
func ErrorAttrKeys(attrs map[string]any) []slog.Attr {
	return []slog.Attr{slog.Any("attr_keys", slices.Sorted(maps.Keys(attrs)))}
}

// ErrorAttrValues logs every attr verbatim, sorted by key: the behavior
// before LoggerConfig existed. Use it only if attrs never hold request data.
func ErrorAttrValues(attrs map[string]any) []slog.Attr {
	out := make([]slog.Attr, 0, len(attrs))
	for _, key := range slices.Sorted(maps.Keys(attrs)) {
		out = append(out, slog.Any(key, attrs[key]))
	}
	return out
}

func (m *LoggerMiddleware) errorAttrs(attrs map[string]any) []slog.Attr {
	if len(attrs) == 0 {
		return nil
	}
	if m.config.ErrorAttrs != nil {
		return m.config.ErrorAttrs(attrs)
	}
	return ErrorAttrKeys(attrs)
}

// appendErrorAttrs adds extra without overwriting a key the line already has.
func appendErrorAttrs(attrs, extra []slog.Attr) []slog.Attr {
	for _, a := range extra {
		if !containsKey(attrs, a.Key) {
			attrs = append(attrs, a)
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
