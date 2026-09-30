// Package requestid gives every request an ID, reusing a valid incoming
// X-Request-Id so logs correlate across proxies, and exposes it to
// handlers, the logger middleware and Raptor's own error lines.
package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/go-raptor/raptor/v4"
)

// Key is where the ID is stored with ctx.Set. The logger middleware and
// Raptor's error and panic lines (raptor v4.6.0+) read the same key.
const Key = "request_id"

// Header is the request and response header carrying the ID.
const Header = "X-Request-Id"

// maxIncomingLength caps a reused incoming ID, so a client can't pad every
// log line.
const maxIncomingLength = 128

type contextKey struct{}

// FromContext returns the request ID stored in a request context, or "".
// Services that get the request's context.Context use it.
func FromContext(ctx context.Context) string {
	id, _ := ctx.Value(contextKey{}).(string)
	return id
}

type RequestIDMiddleware struct {
	raptor.Middleware
}

func NewRequestIDMiddleware() *RequestIDMiddleware {
	return &RequestIDMiddleware{}
}

// Handle reuses a valid incoming X-Request-Id or generates one, echoes it in
// the response, and stores it with ctx.Set and in the request context.
func (m *RequestIDMiddleware) Handle(ctx *raptor.Context, next func(*raptor.Context) error) error {
	req := ctx.Request()
	id := req.Header.Get(Header)
	if !valid(id) {
		id = generate()
	}
	ctx.Set(Key, id)
	ctx.Response().Header().Set(Header, id)
	ctx.SetRequest(req.WithContext(context.WithValue(req.Context(), contextKey{}, id)))
	return next(ctx)
}

// valid accepts 1–128 characters of [A-Za-z0-9._-]: what proxies and load
// balancers generate, and nothing that could split or pollute a log line.
func valid(id string) bool {
	if id == "" || len(id) > maxIncomingLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// generate returns 128 random bits as 32 hex characters.
func generate() string {
	var b [16]byte
	rand.Read(b[:]) // never returns an error (crypto/rand, Go 1.24+)
	return hex.EncodeToString(b[:])
}
