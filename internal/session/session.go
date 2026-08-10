// Package session implements ADR-0049: the browser session is an opaque,
// high-entropy identifier in an HttpOnly cookie, resolved by the BFF against a
// server-side store on every request.
//
// The browser holds a value that means nothing anywhere else. Tenant, actor and
// roles never leave the server, and revocation is deletion: logout, an
// administrative revocation, and a tenant suspension each delete the record, and
// the next request has no session.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
)

// CookieName is the __Host- prefixed session cookie (ADR-0049 decision 1). The
// prefix binds it to the exact origin with no Domain attribute, so a sibling
// subdomain cannot set or read it.
const CookieName = "__Host-gitfrok_session"

// cookieLifetime is the absolute server-side expiry. Sessions are short-lived;
// their loss logs people out rather than losing data.
const cookieLifetime = 24 * time.Hour

// ErrNoSession is returned when a request carries no usable session. It is the
// only thing this package ever says about why: a refusal must not distinguish
// "logged out" from "session expired" from "never logged in" in a way that leaks
// whether an actor exists.
var ErrNoSession = errors.New("session: no usable session")

// Store persists sessions by opaque identifier. The implementation is
// per-environment: Valkey in a cluster (ADR-0023), in-memory in dev.
type Store interface {
	// Create stores the session and returns its identifier. The identifier is
	// opaque and carries no claims; it is a lookup key and nothing else
	// (ADR-0049 decision 2).
	Create(ctx context.Context, read aggregate.ReadContext, ttl time.Duration) (string, error)
	// Load returns the ReadContext a session was issued for, or ErrNoSession.
	// A session cannot be re-pointed at another tenant: the binding was
	// immutable at issue (ADR-0049 decision 6).
	Load(ctx context.Context, id string) (aggregate.ReadContext, error)
	// Delete removes the session. Revocation is deletion, and it is immediate
	// (ADR-0049 decision 4).
	Delete(ctx context.Context, id string) error
}

// Manager sets and reads the session cookie, delegating storage.
type Manager struct {
	store Store
	now   func() time.Time
}

// NewManager wires a Manager onto a store.
func NewManager(store Store) *Manager {
	return &Manager{store: store, now: time.Now}
}

// Begin starts a session for read and returns the identifier. The OIDC exchange
// has already happened; this is where the principal becomes a browser session
// (ADR-0049 decision 7).
func (m *Manager) Begin(ctx context.Context, read aggregate.ReadContext) (string, error) {
	id, err := m.store.Create(ctx, read, cookieLifetime)
	if err != nil {
		return "", err
	}
	return id, nil
}

// ReadContext resolves the session on the request. A request with no session,
// an unknown session, or an expired one is refused (ADR-0049 decision 3).
func (m *Manager) ReadContext(r *http.Request) (aggregate.ReadContext, bool) {
	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		return aggregate.ReadContext{}, false
	}
	read, err := m.store.Load(r.Context(), cookie.Value)
	if err != nil {
		return aggregate.ReadContext{}, false
	}
	if read.TenantID == "" || read.ActorID == "" {
		return aggregate.ReadContext{}, false
	}
	return read, true
}

// SetCookie attaches the session cookie to the response. The value is the
// opaque identifier; nothing derived from the principal is ever written here.
func (m *Manager) SetCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   int(cookieLifetime.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Revoke deletes the session server-side. This is the revocation; the cookie
// Clear is only what stops the browser offering the dead identifier back.
func (m *Manager) Revoke(ctx context.Context, id string) error {
	return m.store.Delete(ctx, id)
}

// Clear expires the session cookie in the browser. The store deletion is the
// revocation; this only stops the browser offering a dead identifier back.
func (m *Manager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// newID returns an opaque identifier with at least 256 bits from a
// cryptographic source (ADR-0049 decision 2).
func newID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
