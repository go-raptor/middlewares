package requestid

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-raptor/raptor/v4/config"
	"github.com/go-raptor/raptor/v4/core"
)

func testResources() *core.Resources {
	r := core.NewResources()
	r.SetConfig(config.NewConfigDefaults())
	r.SetLogHandler(slog.NewTextHandler(io.Discard, nil))
	return r
}

type seen struct{ stored, fromContext string }

// serve runs one request through Handle and reports the ID the handler saw
// through ctx.Get and through the request context.
func serve(t *testing.T, m *RequestIDMiddleware, incoming *string) (*httptest.ResponseRecorder, seen) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if incoming != nil {
		req.Header[Header] = []string{*incoming}
	}
	rec := httptest.NewRecorder()
	ctx := core.NewContext(core.NewCore(testResources()), req, rec)
	var s seen
	if err := m.Handle(ctx, func(c *core.Context) error {
		s.stored, _ = c.Get(Key).(string)
		s.fromContext = FromContext(c.Request().Context())
		return c.NoContent()
	}); err != nil {
		t.Fatal(err)
	}
	return rec, s
}

var generated = regexp.MustCompile(`^[0-9a-f]{32}$`)

func newMiddleware() *RequestIDMiddleware {
	m := NewRequestIDMiddleware()
	m.Init(testResources())
	return m
}

func TestGeneratesID(t *testing.T) {
	rec, s := serve(t, newMiddleware(), nil)
	id := rec.Header().Get(Header)
	if !generated.MatchString(id) {
		t.Fatalf("generated ID %q, want 32 hex characters", id)
	}
	if s.stored != id || s.fromContext != id {
		t.Fatalf("handler saw ctx.Get=%q FromContext=%q, want %q", s.stored, s.fromContext, id)
	}
}

func TestReusesValidIncomingID(t *testing.T) {
	incoming := "abc-123.DEF_4"
	rec, s := serve(t, newMiddleware(), &incoming)
	if got := rec.Header().Get(Header); got != incoming || s.stored != incoming {
		t.Fatalf("a valid incoming ID must be reused: header %q, stored %q", got, s.stored)
	}
}

func TestReplacesInvalidIncomingID(t *testing.T) {
	for _, incoming := range []string{"a b", "a\r\nb", strings.Repeat("x", 129), ""} {
		rec, _ := serve(t, newMiddleware(), &incoming)
		if got := rec.Header().Get(Header); got == incoming || !generated.MatchString(got) {
			t.Errorf("incoming %q: got %q, want a generated ID", incoming, got)
		}
	}
}

func TestGeneratedIDsDiffer(t *testing.T) {
	m := newMiddleware()
	a, _ := serve(t, m, nil)
	b, _ := serve(t, m, nil)
	if a.Header().Get(Header) == b.Header().Get(Header) {
		t.Fatal("two requests got the same generated ID")
	}
}

func TestZeroValueMiddleware(t *testing.T) {
	m := &RequestIDMiddleware{}
	m.Init(testResources())
	if rec, _ := serve(t, m, nil); !generated.MatchString(rec.Header().Get(Header)) {
		t.Fatal("the zero value must work")
	}
}
