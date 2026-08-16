package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	identityv1 "github.com/gitfrok/bff/gen/proto/identity/v1"
	"github.com/gitfrok/bff/internal/session"
)

type stubDiscovery struct{ endpoint string }

func (s stubDiscovery) AuthorizationEndpoint(_ context.Context, _ string) (string, error) {
	return s.endpoint, nil
}

type stubAuthorizer struct {
	principal *identityv1.Principal
	err       error
	lastCode  string
	lastURI   string
}

func (s *stubAuthorizer) ExchangeCode(_ context.Context, code, verifier, redirectURI, nonce string) (*identityv1.Principal, error) {
	s.lastCode = code
	s.lastURI = redirectURI
	return s.principal, s.err
}

func newHandler(auth *stubAuthorizer) (*Handler, *session.Manager) {
	config := Config{
		Issuer:      "https://issuer.gitsaas.test",
		ClientID:    "bff",
		RedirectURI: "https://app.gitsaas.test/callback",
		Scope:       "openid profile email",
	}
	manager := session.NewManager(session.NewMemory())
	return New(config, auth, stubDiscovery{endpoint: "https://issuer.gitsaas.test/oauth/v2/authorize"}, manager), manager
}

// runCallback starts a flow and drives the callback with the returned state
// handle, returning the response so callers can inspect the issued cookie.
func runCallback(t *testing.T, handler *Handler, code string) *httptest.ResponseRecorder {
	t.Helper()
	start := httptest.NewRecorder()
	handler.Routes().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/login", nil))
	flow := start.Result().Cookies()[0]

	callback := httptest.NewRequest(http.MethodGet, "/callback?code="+code+"&state="+flow.Value, nil)
	callback.AddCookie(flow)
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, callback)
	return response
}

// A login request redirects to the issuer's authorization endpoint with a PKCE
// challenge and nonce, and sets an HttpOnly flow cookie.
func TestLoginStartsTheFlow(t *testing.T) {
	handler, _ := newHandler(&stubAuthorizer{})
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login", nil))

	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", response.Code)
	}
	location := response.Header().Get("Location")
	for _, want := range []string{"https://issuer.gitsaas.test/oauth/v2/authorize", "code_challenge=", "code_challenge_method=S256", "nonce=", "state=", "client_id=bff", "response_type=code"} {
		if !strings.Contains(location, want) {
			t.Errorf("location %q missing %q", location, want)
		}
	}
	cookies := response.Result().Cookies()
	var flow *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == flowCookieName {
			flow = cookie
		}
	}
	if flow == nil || !flow.HttpOnly || !flow.Secure {
		t.Fatalf("flow cookie = %+v, want HttpOnly + Secure", flow)
	}
}

// A callback with a matching flow, code and state exchanges the code and
// establishes a session cookie whose value the browser could not have supplied
// itself.
func TestCallbackExchangesAndEstablishesSession(t *testing.T) {
	auth := &stubAuthorizer{principal: &identityv1.Principal{TenantId: "tenant-a", ActorId: "actor-a", Roles: []string{"reader"}}}
	handler, _ := newHandler(auth)

	// Start a flow to obtain the state handle.
	start := httptest.NewRecorder()
	handler.Routes().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/login", nil))
	flow := start.Result().Cookies()[0]

	callback := httptest.NewRequest(http.MethodGet, "/callback?code=abc&state="+flow.Value, nil)
	callback.AddCookie(flow)
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, callback)

	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", response.Code)
	}
	if auth.lastCode != "abc" || auth.lastURI != "https://app.gitsaas.test/callback" {
		t.Fatalf("exchange = code %q uri %q", auth.lastCode, auth.lastURI)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == session.CookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || !sessionCookie.Secure {
		t.Fatalf("session cookie = %+v, want HttpOnly + Secure", sessionCookie)
	}
}

// The session begun at the callback must carry the principal's roles so that
// downstream reads resolve with the actor's authorization (ADR-0049 decision 8).
func TestCallbackEstablishedSessionCarriesPrincipalRoles(t *testing.T) {
	roles := []string{"reader", "maintainer"}
	auth := &stubAuthorizer{principal: &identityv1.Principal{TenantId: "tenant-a", ActorId: "actor-a", Roles: roles}}
	handler, manager := newHandler(auth)

	response := runCallback(t, handler, "abc")
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", response.Code)
	}
	sessionCookie := sessionCookieFrom(t, response)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie)
	read, ok := manager.ReadContext(req)
	if !ok {
		t.Fatal("issued session did not resolve")
	}
	if read.TenantID != "tenant-a" || read.ActorID != "actor-a" {
		t.Fatalf("session identity = %q/%q, want tenant-a/actor-a", read.TenantID, read.ActorID)
	}
	if !reflect.DeepEqual(read.ActorRoles, roles) {
		t.Fatalf("session roles = %v, want %v", read.ActorRoles, roles)
	}
}

// A principal with no roles still yields a session whose role slice is present
// and empty, never dropped: a role-less actor is role-less, not unauthenticated
// (ADR-0049 decision 8).
func TestCallbackEstablishedSessionRolelessPrincipalHasEmptyRoles(t *testing.T) {
	auth := &stubAuthorizer{principal: &identityv1.Principal{TenantId: "tenant-a", ActorId: "actor-a"}}
	handler, manager := newHandler(auth)

	response := runCallback(t, handler, "abc")
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", response.Code)
	}
	sessionCookie := sessionCookieFrom(t, response)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie)
	read, ok := manager.ReadContext(req)
	if !ok {
		t.Fatal("issued session did not resolve")
	}
	if len(read.ActorRoles) != 0 {
		t.Fatalf("session roles = %v, want empty", read.ActorRoles)
	}
}

// sessionCookieFrom pulls the issued session cookie off a callback response.
func sessionCookieFrom(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == session.CookieName {
			return cookie
		}
	}
	t.Fatal("callback set no session cookie")
	return nil
}

// A callback whose state does not match the flow cookie is a hijacked or
// replayed flow and is refused.
func TestCallbackRejectsStateMismatch(t *testing.T) {
	handler, _ := newHandler(&stubAuthorizer{principal: &identityv1.Principal{TenantId: "t", ActorId: "a"}})
	start := httptest.NewRecorder()
	handler.Routes().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/login", nil))
	flow := start.Result().Cookies()[0]

	callback := httptest.NewRequest(http.MethodGet, "/callback?code=abc&state=wrong", nil)
	callback.AddCookie(flow)
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, callback)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

// A refused exchange (empty principal, the one coarse denial) yields no session.
func TestCallbackRefusesFailedExchange(t *testing.T) {
	handler, _ := newHandler(&stubAuthorizer{})
	start := httptest.NewRecorder()
	handler.Routes().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/login", nil))
	flow := start.Result().Cookies()[0]

	callback := httptest.NewRequest(http.MethodGet, "/callback?code=bad&state="+flow.Value, nil)
	callback.AddCookie(flow)
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, callback)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == session.CookieName {
			t.Fatal("a failed exchange set a session cookie")
		}
	}
}

// The discovery port means no network is needed to prove the redirect shape.
