package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/identity"
)

// stubGrants records the identity and requests it was handed and answers
// with canned grant shapes.
type stubGrants struct {
	read      aggregate.ReadContext
	issue     identity.GrantIssue
	grantID   string
	principal string
	grant     identity.Grant
	grants    []identity.Grant
	err       error
	calls     int
}

func (s *stubGrants) IssueGrant(_ context.Context, read aggregate.ReadContext, in identity.GrantIssue) (identity.Grant, error) {
	s.read, s.issue, s.calls = read, in, s.calls+1
	return s.grant, s.err
}

func (s *stubGrants) RevokeGrant(_ context.Context, read aggregate.ReadContext, grantID string) (identity.Grant, error) {
	s.read, s.grantID, s.calls = read, grantID, s.calls+1
	return s.grant, s.err
}

func (s *stubGrants) ListGrants(_ context.Context, read aggregate.ReadContext, auditorPrincipalID string) ([]identity.Grant, error) {
	s.read, s.principal, s.calls = read, auditorPrincipalID, s.calls+1
	return s.grants, s.err
}

func serveGrants(t *testing.T, h *AuditorGrantsHandler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	h.Routes().ServeHTTP(recorder, httptest.NewRequest(method, target, strings.NewReader(body)))
	return recorder
}

const grantBody = `{"auditor_principal_id":"p-auditor","range_from":"2026-07-01T00:00:00Z",` +
	`"range_to":"2026-07-31T23:59:59Z","repository_id":"repo-a","pack_ids":["pack-1"],` +
	`"expires_at":"2026-08-14T00:00:00Z"}`

// An issue is forwarded under the session's verified identity with only the
// scope and requested expiry the contract names — no grant identity, state
// or decision outcome is caller-assertable — and answered with the grant as
// issued (SPEC-0033 AC8).
func TestIssueGrantShapesIssuedGrant(t *testing.T) {
	when := time.Date(2026, 7, 2, 9, 30, 0, 0, time.UTC)
	gr := &stubGrants{grant: identity.Grant{
		GrantID: "grant-1", TenantID: "tenant-a", AuditorPrincipalID: "p-auditor",
		RangeFrom:    time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		RangeTo:      time.Date(2026, 7, 31, 23, 59, 59, 0, time.UTC),
		RepositoryID: "repo-a", PackIDs: []string{"pack-1"},
		ExpiresAt: time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC),
		GrantedBy: "actor-a", IssuedAt: when, State: identity.GrantActive,
	}}
	response := serveGrants(t, NewAuditorGrants(gr, session()), http.MethodPost, "/api/v1/audit/auditor-grants", grantBody)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{
		`"grant_id":"grant-1"`, `"state":"ACTIVE"`, `"granted_by":"actor-a"`,
		`"auditor_principal_id":"p-auditor"`, `"pack_ids":["pack-1"]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	wantFrom := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	wantExpiry := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	if gr.issue.AuditorPrincipalID != "p-auditor" || !gr.issue.RangeFrom.Equal(wantFrom) ||
		gr.issue.RepositoryID != "repo-a" || len(gr.issue.PackIDs) != 1 || !gr.issue.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("issue = %+v", gr.issue)
	}
	// Identity came from the session, never from the body.
	if gr.read.TenantID != "tenant-a" || gr.read.ActorID != "actor-a" || gr.read.RequestID == "" {
		t.Fatalf("context = %+v", gr.read)
	}
}

// A request without a session, a malformed body, or a shape the contract
// does not name is the same coarse refusal as everything else, and none of
// it reaches the backend (SPEC-0033 AC3, SPEC-0001).
func TestIssueGrantMalformedInputIsCoarse(t *testing.T) {
	for _, body := range []string{
		`{not json`,
		`{}`,
		`{"auditor_principal_id":"p-auditor"}`,
		`{"range_from":"2026-07-01T00:00:00Z","range_to":"2026-07-31T23:59:59Z","expires_at":"2026-08-14T00:00:00Z"}`,
		`{"auditor_principal_id":"p-auditor","range_from":"not-a-date","range_to":"2026-07-31T23:59:59Z","expires_at":"2026-08-14T00:00:00Z"}`,
		`{"auditor_principal_id":"p-auditor","range_from":"2026-07-31T23:59:59Z","range_to":"2026-07-01T00:00:00Z","pack_ids":["pack-1"],"expires_at":"2026-08-14T00:00:00Z"}`,
		`{"auditor_principal_id":"p-auditor","range_from":"2026-07-01T00:00:00Z","range_to":"2026-07-31T23:59:59Z","expires_at":"2026-08-14T00:00:00Z"}`,
		`{"auditor_principal_id":"p-auditor","range_from":"2026-07-01T00:00:00Z","range_to":"2026-07-31T23:59:59Z","pack_ids":["pack-1"]}`,
	} {
		gr := &stubGrants{}
		response := serveGrants(t, NewAuditorGrants(gr, session()), http.MethodPost, "/api/v1/audit/auditor-grants", body)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", body, response.Code)
		}
		if gr.calls != 0 {
			t.Fatalf("%s: backend was called for a malformed request", body)
		}
	}
	gr := &stubGrants{}
	response := serveGrants(t, NewAuditorGrants(gr, stubSession{}), http.MethodPost, "/api/v1/audit/auditor-grants", grantBody)
	if response.Code != http.StatusNotFound || gr.calls != 0 {
		t.Fatalf("no-session: status = %d, calls = %d", response.Code, gr.calls)
	}
}

// Revoking names the grant from the path and answers with the grant as
// revoked — state and revocation instant shaped field for field. Revocation
// takes effect on the next decision; this surface only forwards
// (SPEC-0033 AC7).
func TestRevokeGrantShapesRevokedGrant(t *testing.T) {
	when := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	gr := &stubGrants{grant: identity.Grant{
		GrantID: "grant-1", TenantID: "tenant-a", AuditorPrincipalID: "p-auditor",
		ExpiresAt: when.Add(time.Hour), RevokedAt: when, State: identity.GrantRevoked,
	}}
	response := serveGrants(t, NewAuditorGrants(gr, session()), http.MethodDelete, "/api/v1/audit/auditor-grants/grant-1", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if gr.grantID != "grant-1" || gr.read.RequestID == "" {
		t.Fatalf("grant id = %q, context = %+v", gr.grantID, gr.read)
	}
	var view AuditorGrantView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if view.State != "REVOKED" || !view.RevokedAt.Equal(when) {
		t.Fatalf("view = %+v", view)
	}
}

// Listing shapes every grant's scope, state and lifecycle — the server's
// rendering of expiry included — and forwards the optional principal filter
// (SPEC-0033 AC3).
func TestListGrantsShapesLifecycle(t *testing.T) {
	from := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	gr := &stubGrants{grants: []identity.Grant{
		{GrantID: "grant-1", AuditorPrincipalID: "p-auditor", RangeFrom: from, State: identity.GrantActive},
		{GrantID: "grant-2", AuditorPrincipalID: "p-auditor", RangeFrom: from, State: identity.GrantExpired},
	}}
	response := serveGrants(t, NewAuditorGrants(gr, session()), http.MethodGet, "/api/v1/audit/auditor-grants?auditor_principal_id=p-auditor", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if gr.principal != "p-auditor" {
		t.Fatalf("filter = %q", gr.principal)
	}
	var view GrantListView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(view.Grants) != 2 || view.Grants[0].State != "ACTIVE" || view.Grants[1].State != "EXPIRED" {
		t.Fatalf("view = %+v", view)
	}
}

// A backend refusal — nonexistent, cross-tenant, revoked, expired or
// unauthorized alike — is one coarse 404 that distinguishes nothing on
// every route (SPEC-0001, SPEC-0033 AC6).
func TestGrantRoutesAreCoarseOnRefusal(t *testing.T) {
	refusal := errors.New("identity: auditor grant unavailable")
	for _, probe := range []struct {
		method, target, body string
	}{
		{http.MethodPost, "/api/v1/audit/auditor-grants", grantBody},
		{http.MethodDelete, "/api/v1/audit/auditor-grants/grant-1", ""},
		{http.MethodGet, "/api/v1/audit/auditor-grants", ""},
	} {
		gr := &stubGrants{err: refusal}
		response := serveGrants(t, NewAuditorGrants(gr, session()), probe.method, probe.target, probe.body)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s %s: status = %d, want 404", probe.method, probe.target, response.Code)
		}
	}
	// No session is the same refusal and never reaches the backend.
	gr := &stubGrants{}
	response := serveGrants(t, NewAuditorGrants(gr, stubSession{}), http.MethodGet, "/api/v1/audit/auditor-grants", "")
	if response.Code != http.StatusNotFound || gr.calls != 0 {
		t.Fatalf("no-session: status = %d, calls = %d", response.Code, gr.calls)
	}
}
