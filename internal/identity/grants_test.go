package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	identityv1 "github.com/gitfrok/bff/gen/proto/identity/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeService records what crossed the wire and answers with canned
// responses.
type fakeService struct {
	createReq *identityv1.CreateAuditorGrantRequest
	revokeReq *identityv1.RevokeAuditorGrantRequest
	listReq   *identityv1.ListAuditorGrantsRequest
	grant     *identityv1.AuditorGrant
	grants    []*identityv1.AuditorGrant
	err       error
}

func (f *fakeService) CreateAuditorGrant(_ context.Context, req *identityv1.CreateAuditorGrantRequest, _ ...grpc.CallOption) (*identityv1.CreateAuditorGrantResponse, error) {
	f.createReq = req
	return &identityv1.CreateAuditorGrantResponse{Grant: f.grant}, f.err
}

func (f *fakeService) RevokeAuditorGrant(_ context.Context, req *identityv1.RevokeAuditorGrantRequest, _ ...grpc.CallOption) (*identityv1.RevokeAuditorGrantResponse, error) {
	f.revokeReq = req
	return &identityv1.RevokeAuditorGrantResponse{Grant: f.grant}, f.err
}

func (f *fakeService) ListAuditorGrants(_ context.Context, req *identityv1.ListAuditorGrantsRequest, _ ...grpc.CallOption) (*identityv1.ListAuditorGrantsResponse, error) {
	f.listReq = req
	return &identityv1.ListAuditorGrantsResponse{Grants: f.grants}, f.err
}

func read() aggregate.ReadContext {
	return aggregate.ReadContext{
		TenantID: "tenant-a", ActorID: "actor-a", ActorRoles: []string{"owner"}, RequestID: "req-1",
	}
}

func issue() GrantIssue {
	return GrantIssue{
		AuditorPrincipalID: "p-auditor",
		RangeFrom:          time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		RangeTo:            time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
		RepositoryID:       "repo-a",
		PackIDs:            []string{"pack-1"},
		ExpiresAt:          time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
}

// Issuing forwards the requested scope and the session's verified identity
// as the contract context — no grant identity, state, or decision outcome
// has a field to travel in (SPEC-0033 AC8) — and renders the issued grant
// field for field.
func TestIssueGrantForwardsScopeAndIdentity(t *testing.T) {
	when := time.Date(2026, 7, 2, 9, 30, 0, 0, time.UTC)
	service := &fakeService{grant: &identityv1.AuditorGrant{
		GrantId: "grant-1", TenantId: "tenant-a", AuditorPrincipalId: "p-auditor",
		RangeFrom: timestamppb.New(issue().RangeFrom), RangeTo: timestamppb.New(issue().RangeTo),
		RepositoryId: "repo-a", PackIds: []string{"pack-1"},
		ExpiresAt: timestamppb.New(issue().ExpiresAt), GrantedBy: "actor-a",
		IssuedAt: timestamppb.New(when),
		State:    identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_ACTIVE,
	}}
	grant, err := New(service).IssueGrant(context.Background(), read(), issue())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	wire := service.createReq
	if wire.GetContext().GetTenantId() != "tenant-a" || wire.GetContext().GetActorId() != "actor-a" ||
		wire.GetContext().GetRequestId() != "req-1" || len(wire.GetContext().GetActorRoles()) != 1 {
		t.Fatalf("context = %+v", wire.GetContext())
	}
	if wire.GetAuditorPrincipalId() != "p-auditor" || wire.GetRepositoryId() != "repo-a" ||
		len(wire.GetPackIds()) != 1 || wire.GetPackIds()[0] != "pack-1" ||
		!wire.GetRangeFrom().AsTime().Equal(issue().RangeFrom) ||
		!wire.GetRangeTo().AsTime().Equal(issue().RangeTo) ||
		!wire.GetExpiresAt().AsTime().Equal(issue().ExpiresAt) {
		t.Fatalf("wire = %+v", wire)
	}
	if grant.GrantID != "grant-1" || grant.State != GrantActive || grant.GrantedBy != "actor-a" ||
		!grant.IssuedAt.Equal(when) || len(grant.PackIDs) != 1 {
		t.Fatalf("grant = %+v", grant)
	}
}

// A shape the contract does not name — no auditor, an open or inverted
// range, no named packs, no expiry — is refused before anything reaches the
// backend (SPEC-0033 AC3).
func TestIssueGrantMalformedShapeIsRefused(t *testing.T) {
	base := issue()
	cases := map[string]func(in GrantIssue) GrantIssue{
		"no auditor": func(in GrantIssue) GrantIssue { in.AuditorPrincipalID = ""; return in },
		"no from":    func(in GrantIssue) GrantIssue { in.RangeFrom = time.Time{}; return in },
		"no to":      func(in GrantIssue) GrantIssue { in.RangeTo = time.Time{}; return in },
		"inverted":   func(in GrantIssue) GrantIssue { in.RangeFrom, in.RangeTo = in.RangeTo, in.RangeFrom; return in },
		"no packs":   func(in GrantIssue) GrantIssue { in.PackIDs = nil; return in },
		"no expiry":  func(in GrantIssue) GrantIssue { in.ExpiresAt = time.Time{}; return in },
	}
	for name, mutate := range cases {
		service := &fakeService{}
		if _, err := New(service).IssueGrant(context.Background(), read(), mutate(base)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%s: err = %v, want ErrMalformed", name, err)
		}
		if service.createReq != nil {
			t.Fatalf("%s: backend was called for a malformed issue", name)
		}
	}
}

// Revoking names the grant and forwards the verified identity; the revoked
// grant — state and revocation instant — renders field for field.
func TestRevokeGrantShapesTransition(t *testing.T) {
	when := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	service := &fakeService{grant: &identityv1.AuditorGrant{
		GrantId: "grant-1", TenantId: "tenant-a", AuditorPrincipalId: "p-auditor",
		ExpiresAt: timestamppb.New(when.Add(time.Hour)),
		RevokedAt: timestamppb.New(when),
		State:     identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_REVOKED,
	}}
	grant, err := New(service).RevokeGrant(context.Background(), read(), "grant-1")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if service.revokeReq.GetGrantId() != "grant-1" || service.revokeReq.GetContext().GetActorId() != "actor-a" {
		t.Fatalf("wire = %+v", service.revokeReq)
	}
	if grant.State != GrantRevoked || !grant.RevokedAt.Equal(when) {
		t.Fatalf("grant = %+v", grant)
	}
	// An unnamed grant is refused before anything reaches the backend.
	if _, err := New(&fakeService{}).RevokeGrant(context.Background(), read(), ""); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty grant id: err = %v, want ErrMalformed", err)
	}
}

// Listing forwards the optional principal filter and renders every grant's
// scope, state and lifecycle — the server's rendering of expiry included
// (SPEC-0033 AC3).
func TestListGrantsShapesLifecycle(t *testing.T) {
	service := &fakeService{grants: []*identityv1.AuditorGrant{
		{GrantId: "grant-1", AuditorPrincipalId: "p-auditor", State: identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_ACTIVE},
		{GrantId: "grant-2", AuditorPrincipalId: "p-auditor", State: identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_EXPIRED},
	}}
	grants, err := New(service).ListGrants(context.Background(), read(), "p-auditor")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if service.listReq.GetAuditorPrincipalId() != "p-auditor" || service.listReq.GetContext().GetTenantId() != "tenant-a" {
		t.Fatalf("wire = %+v", service.listReq)
	}
	if len(grants) != 2 || grants[0].State != GrantActive || grants[1].State != GrantExpired {
		t.Fatalf("grants = %+v", grants)
	}
}

// A backend refusal — the one coarse shape for nonexistent, cross-tenant,
// revoked, expired and unauthorized alike (SPEC-0001) — passes through
// untouched on every operation.
func TestBackendRefusalsPassThrough(t *testing.T) {
	refusal := errors.New("rpc error: code = PermissionDenied desc = auditor grant unavailable")
	for name, call := range map[string]func(c *Client) error{
		"issue":  func(c *Client) error { _, err := c.IssueGrant(context.Background(), read(), issue()); return err },
		"revoke": func(c *Client) error { _, err := c.RevokeGrant(context.Background(), read(), "grant-1"); return err },
		"list":   func(c *Client) error { _, err := c.ListGrants(context.Background(), read(), ""); return err },
	} {
		if err := call(New(&fakeService{err: refusal})); !errors.Is(err, refusal) {
			t.Fatalf("%s: err = %v, want the backend refusal untouched", name, err)
		}
	}
}

// A state the wire does not name renders empty rather than inventing one:
// UNSPECIFIED is the absence of a state, never a state a grant holds.
func TestUnspecifiedStateRendersEmpty(t *testing.T) {
	service := &fakeService{grants: []*identityv1.AuditorGrant{{GrantId: "grant-1"}}}
	grants, err := New(service).ListGrants(context.Background(), read(), "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(grants) != 1 || grants[0].State != "" {
		t.Fatalf("grants = %+v", grants)
	}
}
