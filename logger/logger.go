package logger

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
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
	status := ctx.Response().Status

	attrs := []any{
		"ip", ctx.RealIP(),
		"method", ctx.Request().Method,
		"path", ctx.Request().URL.Path,
		"status", status,
		"duration", formatDuration(time.Since(startTime)),
	}

	if err == nil {
		attrs = append(attrs, "handler", core.ActionDescriptor(ctx.Controller(), ctx.Action()))
		m.Log.Log(context.Background(), slog.LevelInfo, "Request processed", attrs...)
		return
	}

	message := "Error while processing request"
	if status == http.StatusNotFound {
		message = "Handler not found"
	}
	if raptorErr, ok := err.(*errs.Error); ok {
		attrs = append(attrs, "message", raptorErr.Message)
		attrs = appendErrorAttrs(attrs, raptorErr.AttrsToSlice())
	}
	m.Log.Log(context.Background(), slog.LevelError, message, attrs...)
}

func formatDuration(d time.Duration) string {
	switch {
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%dµs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

func appendErrorAttrs(attrs, errAttrs []any) []any {
	for i := 0; i+1 < len(errAttrs); i += 2 {
		if !containsKey(attrs, errAttrs[i]) {
			attrs = append(attrs, errAttrs[i], errAttrs[i+1])
		}
	}
	return attrs
}

func containsKey(attrs []any, key any) bool {
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == key {
			return true
		}
	}
	return false
}
