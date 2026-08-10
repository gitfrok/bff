package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
)

// A session that was begun is loadable, and the browser only ever sees the
// opaque identifier — never a tenant, actor, or role (ADR-0049 decision 2).
func TestBeginAndLoadRoundTrip(t *testing.T) {
	store := NewMemory()
	manager := NewManager(store)
	read := aggregate.ReadContext{TenantID: "tenant-a", ActorID: "actor-a", RequestID: "request-a", ActorRoles: []string{"reader"}}

	id, err := manager.Begin(t.Context(), read)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if id == "" {
		t.Fatal("Begin returned an empty identifier")
	}
	if len(id) < 40 {
		t.Fatalf("identifier %q is shorter than 256 bits of entropy would be", id)
	}

	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(&http.Cookie{Name: CookieName, Value: id})
	got, ok := manager.ReadContext(request)
	if !ok {
		t.Fatal("ReadContext failed for a live session")
	}
	if got.TenantID != "tenant-a" || got.ActorID != "actor-a" {
		t.Fatalf("ReadContext = %+v", got)
	}
}

// An unknown, empty, or expired session is refused the same way (ADR-0049
// decision 3): the refusal says nothing about what exists.
func TestNoSessionIsRefused(t *testing.T) {
	manager := NewManager(NewMemory())
	for _, value := range []string{"", "unknown-id"} {
		request := httptest.NewRequest("GET", "/", nil)
		if value != "" {
			request.AddCookie(&http.Cookie{Name: CookieName, Value: value})
		}
		if _, ok := manager.ReadContext(request); ok {
			t.Fatalf("cookie %q was accepted", value)
		}
	}
}

// Revocation is deletion and it is immediate: the next request has no session
// (ADR-0049 decision 4).
func TestRevokeDeletesImmediately(t *testing.T) {
	store := NewMemory()
	manager := NewManager(store)
	id, err := manager.Begin(t.Context(), aggregate.ReadContext{TenantID: "t", ActorID: "a", RequestID: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Revoke(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(t.Context(), id); err != ErrNoSession {
		t.Fatalf("Load after Revoke = %v, want ErrNoSession", err)
	}
}

// A session expires server-side; expiry is not a distinguishable refusal.
func TestExpiryRefuses(t *testing.T) {
	store := NewMemory()
	manager := NewManager(store)
	id, err := manager.Begin(t.Context(), aggregate.ReadContext{TenantID: "t", ActorID: "a", RequestID: "r"})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Now().Add(2 * cookieLifetime) }
	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(&http.Cookie{Name: CookieName, Value: id})
	if _, ok := manager.ReadContext(request); ok {
		t.Fatal("an expired session was accepted")
	}
}
