// Package login serves the browser half of the OIDC Authorization Code Flow
// with PKCE (ADR-0045, T-0013).
//
// The BFF performs the redirect dance; Identity&Access performs the
// cryptographic verification and claim-to-principal mapping through ExchangeCode
// (contracts/proto/identity/v1/identity_oidc.proto). The OIDC client secret
// never leaves the backend. The authorization code, the PKCE verifier and the
// ID token are never stored and never returned to the browser (ADR-0049
// decision 7).
package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	identityv1 "github.com/gitfrok/bff/gen/proto/identity/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/session"
)

// Config is the per-environment OIDC client configuration. Every value is
// configured, never compiled in (invariant 13); the issuer's metadata and
// tenant mapping stay with Identity&Access.
type Config struct {
	// Issuer is the OIDC discovery base URL (e.g. https://zitadel.gitsaas.test).
	Issuer string
	// ClientID names this application with the issuer.
	ClientID string
	// RedirectURI is the browser callback the issuer sends the code to.
	RedirectURI string
	// Scope is the OIDC scope set. openid is required; profile and email are
	// typical for the claim vocabulary the tenant mapping reads.
	Scope string
}

// Authorizer exchanges codes through the backend's verified surface.
type Authorizer interface {
	// ExchangeCode completes the flow and returns the tenant-scoped principal.
	ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI, nonce string) (*identityv1.Principal, error)
}

// Discovery reads the issuer's OIDC metadata. It is a port so tests never
// touch the network.
type Discovery interface {
	// AuthorizationEndpoint returns the issuer's authorization_endpoint.
	AuthorizationEndpoint(ctx context.Context, issuer string) (string, error)
}

// Handler serves the login start and callback routes.
type Handler struct {
	config     Config
	authorizer Authorizer
	discovery  Discovery
	sessions   *session.Manager
	now        func() time.Time

	mu    sync.Mutex
	flows map[string]start
}

// New wires the login handler.
func New(config Config, authorizer Authorizer, discovery Discovery, sessions *session.Manager) *Handler {
	return &Handler{
		config:     config,
		authorizer: authorizer,
		discovery:  discovery,
		sessions:   sessions,
		now:        time.Now,
		flows:      make(map[string]start),
	}
}

// nonceLifetime bounds how long a begun flow stays valid. A code delivered
// after this has expired is refused rather than exchanged.
const nonceLifetime = 10 * time.Minute

// Routes returns the login surface. /login starts the flow with a PKCE
// challenge; /callback receives the code, exchanges it, and establishes the
// session; /logout revokes the session.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", h.login)
	mux.HandleFunc("GET /callback", h.callback)
	mux.HandleFunc("POST /logout", h.logout)
	return mux
}

// start is the state a begun flow carries. The verifier and nonce are never
// written anywhere a script could read; they live only in this server-side map
// keyed by a random handle the browser holds in a cookie.
type start struct {
	verifier  string
	nonce     string
	expiresAt time.Time
}

// login begins the flow: it generates the PKCE pair and nonce, records them
// server-side, and redirects to the issuer's authorization endpoint.
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	verifier, challenge, err := pkce()
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	nonce, err := randomString(16)
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}

	// The flow handle is itself an opaque identifier: high-entropy, carried in a
	// cookie, resolved server-side — the same shape as the session it will
	// become. It is not the session; it expires with the flow.
	handle, err := randomString(16)
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	h.mu.Lock()
	h.flows[handle] = start{verifier: verifier, nonce: nonce, expiresAt: h.now().Add(nonceLifetime)}
	h.mu.Unlock()

	authURL, err := h.authorizeURL(r.Context(), challenge, nonce, handle)
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    handle,
		Path:     "/",
		MaxAge:   int(nonceLifetime.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

// callback receives the code from the issuer, exchanges it, and turns the
// resulting principal into a browser session.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	// The OIDC error shape: an issuer can refuse the flow, and that refusal is
	// not a reason to distinguish anything about a user.
	if errValue := r.URL.Query().Get("error"); errValue != "" {
		http.Error(w, "login failed", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "login failed", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(flowCookieName)
	if err != nil {
		http.Error(w, "login failed", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	flow, ok := h.flows[cookie.Value]
	delete(h.flows, cookie.Value)
	h.mu.Unlock()
	if !ok || h.now().After(flow.expiresAt) {
		http.Error(w, "login failed", http.StatusBadRequest)
		return
	}
	if state != cookie.Value {
		// The state carried in the URL and the flow handle in the cookie must
		// agree; a mismatch is a hijacked or replayed flow.
		http.Error(w, "login failed", http.StatusBadRequest)
		return
	}

	principal, err := h.authorizer.ExchangeCode(r.Context(), code, flow.verifier, h.config.RedirectURI, flow.nonce)
	if err != nil || principal == nil || principal.GetTenantId() == "" || principal.GetActorId() == "" {
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}

	id, err := h.sessions.Begin(r.Context(), aggregate.ReadContext{
		TenantID:  principal.GetTenantId(),
		ActorID:   principal.GetActorId(),
		RequestID: newRequestID(),
	})
	if err != nil {
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	h.sessions.SetCookie(w, id)
	http.Redirect(w, r, "/", http.StatusFound)
}

// logout revokes the server-side session and clears the cookie.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(session.CookieName); err == nil && cookie.Value != "" {
		_ = h.sessions.Revoke(r.Context(), cookie.Value)
	}
	h.sessions.Clear(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// authorizeURL builds the issuer's authorization endpoint URL.
func (h *Handler) authorizeURL(ctx context.Context, challenge, nonce, state string) (string, error) {
	endpoint, err := h.discovery.AuthorizationEndpoint(ctx, h.config.Issuer)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("response_type", "code")
	query.Set("client_id", h.config.ClientID)
	query.Set("redirect_uri", h.config.RedirectURI)
	query.Set("scope", h.config.Scope)
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// HTTPDiscovery reads the issuer's discovery document over HTTP.
type HTTPDiscovery struct {
	// Client is the HTTP client used for the discovery fetch. The caller owns
	// its lifecycle; it is injected so tests can stub it.
	Client *http.Client
}

// AuthorizationEndpoint implements Discovery.
func (d HTTPDiscovery) AuthorizationEndpoint(ctx context.Context, issuer string) (string, error) {
	base, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("login: issuer %q: %w", issuer, err)
	}
	base.Path = base.Path + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return "", err
	}
	response, err := d.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("login: discover %s: %w", base.String(), err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login: discover %s: status %d", base.String(), response.StatusCode)
	}
	var document struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return "", fmt.Errorf("login: discover %s: %w", base.String(), err)
	}
	if document.AuthorizationEndpoint == "" {
		return "", fmt.Errorf("login: discover %s: no authorization_endpoint", base.String())
	}
	return document.AuthorizationEndpoint, nil
}

// pkce generates an S256 code-verifier/challenge pair per RFC 7636.
func pkce() (verifier, challenge string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func randomString(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func newRequestID() string {
	id, err := randomString(8)
	if err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return id
}

const flowCookieName = "__Host-gitfrok_login"
