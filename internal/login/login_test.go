package login

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func newHandler(auth *stubAuthorizer) *Handler {
	config := Config{
		Issuer:      "https://issuer.gitsaas.test",
		ClientID:    "bff",
		RedirectURI: "https://app.gitsaas.test/callback",
		Scope:       "openid profile email",
	}
	manager := session.NewManager(session.NewMemory())
	return New(config, auth, stubDiscovery{endpoint: "https://issuer.gitsaas.test/oauth/v2/authorize"}, manager)
}

// A login request redirects to the issuer's authorization endpoint with a PKCE
// challenge and nonce, and sets an HttpOnly flow cookie.
func TestLoginStartsTheFlow(t *testing.T) {
	handler := newHandler(&stubAuthorizer{})
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
	handler := newHandler(auth)

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

// A callback whose state does not match the flow cookie is a hijacked or
// replayed flow and is refused.
func TestCallbackRejectsStateMismatch(t *testing.T) {
	handler := newHandler(&stubAuthorizer{principal: &identityv1.Principal{TenantId: "t", ActorId: "a"}})
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
	handler := newHandler(&stubAuthorizer{})
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
