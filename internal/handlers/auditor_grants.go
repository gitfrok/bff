// auditor_grants.go is the auditor grant administration surface (SPEC-0033,
// T-0027, PRD PR-18). The backend Identity & Access service is the PDP for
// auditor.grant.manage: issuing, revoking and listing are owner-only
// decisions, each lifecycle action appends the immutable audit record
// naming the granting admin and the auditor principal, and every failure —
// nonexistent, cross-tenant, revoked, expired, malformed or unauthorized —
// is the one coarse refusal (SPEC-0001). This surface forwards the
// session's verified identity and shapes only (invariant 18): it carries no
// permission logic, no role toggle and no grant state of its own — the
// grant's validity is a fact the backend reads at decision time (SPEC-0033
// AC5/AC7). What a request accepts is the scope the contract names and
// nothing else: no grant identity, state, extension or renewal has a field
// to travel in (SPEC-0033 AC8).
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/identity"
)

// AuditorGrants is the grant port this surface shapes. The backend owns
// every decision: authorization, idempotency, expiry recognition and audit
// (SPEC-0033).
type AuditorGrants interface {
	IssueGrant(ctx context.Context, read aggregate.ReadContext, in identity.GrantIssue) (identity.Grant, error)
	RevokeGrant(ctx context.Context, read aggregate.ReadContext, grantID string) (identity.Grant, error)
	ListGrants(ctx context.Context, read aggregate.ReadContext, auditorPrincipalID string) ([]identity.Grant, error)
}

// AuditorGrantsHandler serves the auditor grant surface.
type AuditorGrantsHandler struct {
	grants  AuditorGrants
	session Session
}

// NewAuditorGrants wires the handler onto the grant port.
func NewAuditorGrants(grants AuditorGrants, session Session) *AuditorGrantsHandler {
	return &AuditorGrantsHandler{grants: grants, session: session}
}

// Routes returns the auditor grant surface. Identity never comes from these
// paths or parameters — only from the authenticated session.
func (h *AuditorGrantsHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/audit/auditor-grants", h.issueGrant)
	mux.HandleFunc("DELETE /api/v1/audit/auditor-grants/{grant_id}", h.revokeGrant)
	mux.HandleFunc("GET /api/v1/audit/auditor-grants", h.listGrants)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux, as the
// evidence handler does.
func (h *AuditorGrantsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

// grantIssueBody is the JSON shape the request posts. It mirrors the
// contract's CreateAuditorGrantRequest minus everything the session
// supplies or the server assigns: no tenant, actor, role, grant identity,
// state or version is caller-assertable — the request names only the scope
// and the requested expiry (SPEC-0033 AC8).
type grantIssueBody struct {
	AuditorPrincipalID string   `json:"auditor_principal_id"`
	RangeFrom          string   `json:"range_from"`
	RangeTo            string   `json:"range_to"`
	RepositoryID       string   `json:"repository_id"`
	PackIDs            []string `json:"pack_ids"`
	ExpiresAt          string   `json:"expires_at"`
}

// maxGrantIssueBodyBytes bounds the request body: a principal, a closed
// range, an optional repository scope, the named packs and an expiry is a
// handful of fields, and nothing legitimate approaches this.
const maxGrantIssueBodyBytes = 16 << 10

// AuditorGrantView is one grant record as the caller observes it: scope,
// state and lifecycle only — never pack contents. The state is the server's
// rendering of its own record at response time, never an authorization
// outcome this surface produces (SPEC-0033 AC7).
type AuditorGrantView struct {
	GrantID            string    `json:"grant_id"`
	TenantID           string    `json:"tenant_id"`
	AuditorPrincipalID string    `json:"auditor_principal_id"`
	RangeFrom          time.Time `json:"range_from"`
	RangeTo            time.Time `json:"range_to"`
	RepositoryID       string    `json:"repository_id,omitempty"`
	PackIDs            []string  `json:"pack_ids"`
	ExpiresAt          time.Time `json:"expires_at"`
	GrantedBy          string    `json:"granted_by"`
	IssuedAt           time.Time `json:"issued_at"`
	RevokedAt          time.Time `json:"revoked_at,omitempty"`
	State              string    `json:"state"`
}

// GrantListView is the tenant's grants for administration.
type GrantListView struct {
	Grants []AuditorGrantView `json:"grants"`
}

// issueGrant forwards the requested scope to the backend, which decides
// (auditor.grant.manage, owner-only) and answers with the grant as issued:
// server-assigned identity, state and the expiry it recognized — which may
// bound the requested one. A shape the contract does not name is refused
// here, before anything reaches the backend.
func (h *AuditorGrantsHandler) issueGrant(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedAuditorGrants(w)
		return
	}
	var in grantIssueBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGrantIssueBodyBytes)).Decode(&in); err != nil {
		deniedAuditorGrants(w)
		return
	}
	issue, ok := grantIssueOf(in)
	if !ok {
		deniedAuditorGrants(w)
		return
	}
	read.RequestID = newRequestID()
	grant, err := h.grants.IssueGrant(r.Context(), read, issue)
	if err != nil {
		deniedAuditorGrants(w)
		return
	}
	writeJSON(w, grantView(grant))
}

// grantIssueOf parses the posted body into the port's issue shape. false
// names a shape the contract does not name: unparseable timestamps, an open
// or inverted range, no auditor, no named packs, or no requested expiry —
// the same coarse refusal as everything else.
func grantIssueOf(in grantIssueBody) (identity.GrantIssue, bool) {
	rangeFrom, err := time.Parse(time.RFC3339, in.RangeFrom)
	if err != nil {
		return identity.GrantIssue{}, false
	}
	rangeTo, err := time.Parse(time.RFC3339, in.RangeTo)
	if err != nil {
		return identity.GrantIssue{}, false
	}
	expiresAt, err := time.Parse(time.RFC3339, in.ExpiresAt)
	if err != nil {
		return identity.GrantIssue{}, false
	}
	issue := identity.GrantIssue{
		AuditorPrincipalID: in.AuditorPrincipalID,
		RangeFrom:          rangeFrom,
		RangeTo:            rangeTo,
		RepositoryID:       in.RepositoryID,
		PackIDs:            in.PackIDs,
		ExpiresAt:          expiresAt,
	}
	return issue, identity.ValidateGrantIssue(issue)
}

// revokeGrant terminates a grant. Revocation takes effect on the next
// decision, not the next cache cycle: the backend reads the grant's state
// fresh at decision time (SPEC-0033 AC7). The grant comes from the path;
// identity comes from the session.
func (h *AuditorGrantsHandler) revokeGrant(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedAuditorGrants(w)
		return
	}
	grantID := r.PathValue("grant_id")
	if grantID == "" {
		deniedAuditorGrants(w)
		return
	}
	read.RequestID = newRequestID()
	grant, err := h.grants.RevokeGrant(r.Context(), read, grantID)
	if err != nil {
		deniedAuditorGrants(w)
		return
	}
	writeJSON(w, grantView(grant))
}

// listGrants pages the tenant's grants for administration, optionally
// narrowed to one auditor principal by query. Scope, state and lifecycle
// only — never pack contents.
func (h *AuditorGrantsHandler) listGrants(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedAuditorGrants(w)
		return
	}
	read.RequestID = newRequestID()
	grants, err := h.grants.ListGrants(r.Context(), read, r.URL.Query().Get("auditor_principal_id"))
	if err != nil {
		deniedAuditorGrants(w)
		return
	}
	view := GrantListView{Grants: make([]AuditorGrantView, 0, len(grants))}
	for _, grant := range grants {
		view.Grants = append(view.Grants, grantView(grant))
	}
	writeJSON(w, view)
}

// grantView shapes one grant field for field: the adapter adds nothing and
// drops nothing.
func grantView(grant identity.Grant) AuditorGrantView {
	return AuditorGrantView{
		GrantID:            grant.GrantID,
		TenantID:           grant.TenantID,
		AuditorPrincipalID: grant.AuditorPrincipalID,
		RangeFrom:          grant.RangeFrom,
		RangeTo:            grant.RangeTo,
		RepositoryID:       grant.RepositoryID,
		PackIDs:            grant.PackIDs,
		ExpiresAt:          grant.ExpiresAt,
		GrantedBy:          grant.GrantedBy,
		IssuedAt:           grant.IssuedAt,
		RevokedAt:          grant.RevokedAt,
		State:              string(grant.State),
	}
}

// deniedAuditorGrants is the one refusal this surface returns: it
// distinguishes nothing about what exists, what is allowed, or why —
// nonexistent, cross-tenant, revoked, expired and unauthorized are the same
// shape (SPEC-0001, SPEC-0033 AC6).
func deniedAuditorGrants(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "auditor grants unavailable", http.StatusNotFound)
}
