package logger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-raptor/raptor/v4/config"
	"github.com/go-raptor/raptor/v4/core"
	"github.com/go-raptor/raptor/v4/errs"
)

type captured struct {
	ctx context.Context
	rec slog.Record
}

func (c captured) attr(key string) (slog.Value, bool) {
	var val slog.Value
	found := false
	c.rec.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val, found = a.Value, true
			return false
		}
		return true
	})
	return val, found
}

type capturingHandler struct{ records []captured }

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) Handle(ctx context.Context, r slog.Record) error {
	h.records = append(h.records, captured{ctx: ctx, rec: r})
	return nil
}
func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

func run(t *testing.T, req *http.Request, next func(*core.Context) error) captured {
	t.Helper()
	return runWith(t, &LoggerMiddleware{}, req, next)
}

func runWith(t *testing.T, m *LoggerMiddleware, req *http.Request, next func(*core.Context) error) captured {
	t.Helper()
	cap := &capturingHandler{}
	r := core.NewResources()
	r.SetConfig(config.NewConfigDefaults())
	r.SetLogHandler(cap)

	m.Init(r)

	ctx := core.NewContext(core.NewCore(r), req, httptest.NewRecorder())
	_ = m.Handle(ctx, next)

	if len(cap.records) != 1 {
		t.Fatalf("expected exactly 1 log record, got %d", len(cap.records))
	}
	return cap.records[0]
}

// line renders a captured record the way a text log prints it.
func line(t *testing.T, c captured) string {
	t.Helper()
	var buf bytes.Buffer
	if err := slog.NewTextHandler(&buf, nil).Handle(c.ctx, c.rec); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestWrappedErrorAttrKeysAreLogged(t *testing.T) {
	wrapped := fmt.Errorf("service failed: %w", errs.NewErrorBadRequest("bad thing", "field", "name"))
	rec := run(t, httptest.NewRequest(http.MethodGet, "/things", nil), func(c *core.Context) error {
		c.Status(http.StatusBadRequest)
		return wrapped
	})

	if msg, ok := rec.attr("message"); !ok || msg.String() != "bad thing" {
		t.Fatalf("a wrapped errs.Error's message must be logged (requires errors.As, not a bare type assertion); got %q ok=%v", msg.String(), ok)
	}
	if keys, ok := rec.attr("attr_keys"); !ok || fmt.Sprint(keys.Any()) != "[field]" {
		t.Fatalf("a wrapped errs.Error's attr keys must be logged; got %v ok=%v", keys, ok)
	}
	if _, ok := rec.attr("field"); ok {
		t.Fatal("attr values must not be logged by default")
	}
}

func TestErrorAttrValuesNotLoggedByDefault(t *testing.T) {
	rec := run(t, httptest.NewRequest(http.MethodPost, "/login", nil), func(c *core.Context) error {
		c.Status(http.StatusUnprocessableEntity)
		return errs.NewErrorUnprocessableEntity("x", "password", "hunter2")
	})
	out := line(t, rec)
	if strings.Contains(out, "hunter2") {
		t.Fatalf("an attr value reached the log: %s", out)
	}
	if !strings.Contains(out, "attr_keys=[password]") {
		t.Fatalf("attr keys should be logged: %s", out)
	}
}

func TestErrorAttrsConfigurable(t *testing.T) {
	req := func() *http.Request { return httptest.NewRequest(http.MethodPost, "/users", nil) }

	rec := runWith(t, NewLoggerMiddleware(LoggerConfig{ErrorAttrs: ErrorAttrValues}), req(), func(c *core.Context) error {
		return errs.NewErrorBadRequest("bad", "field", "name")
	})
	if f, ok := rec.attr("field"); !ok || f.String() != "name" {
		t.Fatalf("ErrorAttrValues must log values verbatim; got %v ok=%v", f, ok)
	}

	onlyConstraint := func(a map[string]any) []slog.Attr { return []slog.Attr{slog.Any("constraint", a["constraint"])} }
	rec = runWith(t, NewLoggerMiddleware(LoggerConfig{ErrorAttrs: onlyConstraint}), req(), func(c *core.Context) error {
		return errs.NewErrorConflict("duplicate", "constraint", "users_email_key", "email", "a@b.example")
	})
	if v, ok := rec.attr("constraint"); !ok || v.String() != "users_email_key" {
		t.Fatalf("custom ErrorAttrs must be used; got %v ok=%v", v, ok)
	}
	if out := line(t, rec); strings.Contains(out, "a@b.example") {
		t.Fatalf("custom ErrorAttrs leaked an unselected value: %s", out)
	}
}

func TestResourceNotFoundNotLabeledHandlerNotFound(t *testing.T) {
	rec := run(t, httptest.NewRequest(http.MethodGet, "/courses/9", nil), func(c *core.Context) error {
		c.Status(http.StatusNotFound)
		return errs.NewErrorNotFound("course not found")
	})

	if rec.rec.Message == "Handler not found" {
		t.Fatal("a resource 404 returned from a handler must not be logged as \"Handler not found\" — that conflates it with a routing miss")
	}
	if msg, ok := rec.attr("message"); !ok || msg.String() != "course not found" {
		t.Fatalf("the resource-404 message should be logged; got %q", msg.String())
	}
}

type ctxKey string

func TestRequestContextPropagatedToLogger(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKey("trace"), "abc123"))

	rec := run(t, req, func(c *core.Context) error { return c.Status(http.StatusOK) })

	if rec.ctx.Value(ctxKey("trace")) != "abc123" {
		t.Fatal("the logger must pass the request context to the slog handler (so trace IDs propagate), not context.Background()")
	}
}

func TestSuccessLogsHandlerAndBasics(t *testing.T) {
	rec := run(t, httptest.NewRequest(http.MethodPost, "/courses", nil), func(c *core.Context) error {
		return c.Status(http.StatusCreated)
	})

	if rec.rec.Message != "Request processed" {
		t.Fatalf("success message: got %q", rec.rec.Message)
	}
	if rec.rec.Level != slog.LevelInfo {
		t.Fatalf("success level: got %v, want INFO", rec.rec.Level)
	}
	for _, k := range []string{"ip", "method", "path", "status", "duration", "handler"} {
		if _, ok := rec.attr(k); !ok {
			t.Errorf("missing expected attr %q", k)
		}
	}
	if v, ok := rec.attr("status"); !ok || v.Int64() != http.StatusCreated {
		t.Errorf("status attr: got %v", v)
	}
}

func BenchmarkLogRequestSuccess(b *testing.B) {
	r := core.NewResources()
	r.SetConfig(config.NewConfigDefaults())
	r.SetLogHandler(slog.NewTextHandler(io.Discard, nil))

	m := &LoggerMiddleware{}
	m.Init(r)

	req := httptest.NewRequest(http.MethodGet, "/things/42", nil)
	ctx := core.NewContext(core.NewCore(r), req, httptest.NewRecorder())
	next := func(c *core.Context) error { return c.Status(http.StatusOK) }

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Handle(ctx, next)
	}
}
