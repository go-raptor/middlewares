package logger

import (
	"context"
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

func (m *LoggerMiddleware) Handle(c *raptor.Context, next func(*raptor.Context) error) error {
	startTime := time.Now()
	err := next(c)
	m.logRequest(c, startTime, err)
	return err
}

func (m *LoggerMiddleware) logRequest(ctx *raptor.Context, startTime time.Time, err error) {
	durationSinceStart := time.Since(startTime)
	var duration float64
	if durationSinceStart < time.Millisecond {
		duration = float64(durationSinceStart.Microseconds()) / 1000
	} else {
		duration = float64(durationSinceStart.Milliseconds())
	}

	attrs := []any{
		"ip", ctx.RealIP(),
		"method", ctx.Request().Method,
		"path", ctx.Request().URL.Path,
		"duration", duration,
	}

	var (
		logLevel slog.Level
		message  string
		status   int
	)

	if err == nil {
		logLevel = slog.LevelInfo
		message = "Request processed"
		attrs = append(attrs,
			"status", ctx.Response().Status,
			"handler", core.ActionDescriptor(ctx.Controller(), ctx.Action()),
		)
		ctx.Core().Resources.Log.Log(context.Background(), logLevel, message, attrs...)
		return
	}

	logLevel = slog.LevelError
	if raptorErr, ok := err.(*errs.Error); ok {
		status = raptorErr.Code
		if status == http.StatusNotFound {
			message = "Handler not found"
		} else {
			message = "Error while processing request"
		}
		attrs = append(attrs, "message", raptorErr.Message)
		errAttrs := raptorErr.AttrsToSlice()
		for i := 0; i < len(errAttrs); i += 2 {
			if i+1 < len(errAttrs) {
				key := errAttrs[i]
				keyExists := false
				for j := 0; j < len(attrs); j += 2 {
					if j+1 < len(attrs) && attrs[j] == key {
						keyExists = true
						break
					}
				}
				if !keyExists {
					attrs = append(attrs, errAttrs[i], errAttrs[i+1])
				}
			}
		}
	} else {
		status = http.StatusInternalServerError
	}

	attrs = append(attrs, "status", status)
	m.Resources.Log.Log(context.Background(), logLevel, message, attrs...)
}
