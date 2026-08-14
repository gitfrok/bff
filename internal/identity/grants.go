// Package identity adapts the generated AuditorGrantService gRPC client
// onto BFF-shaped request/response types. It carries verified identity and
// shapes only (SPEC-0033, T-0027): the backend is the PDP for
// auditor.grant.manage, every lifecycle action is itself audited, and
// nothing here authorizes, stores, or re-scopes a grant (invariant 18). A
// grant's state, expiry and scope are server facts rendered by Identity &
// Access at response time — never caller claims, and never an input this
// adapter could inject into a decision (SPEC-0033 AC7/AC8).
package identity

import (
	"context"
	"errors"
	"slices"
	"time"

	identityv1 "github.com/gitfrok/bff/gen/proto/identity/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ErrMalformed refuses a request whose shape the contract does not name. It
// is coarse: the caller learns nothing about what exists or what is allowed.
var ErrMalformed = errors.New("identity: malformed grant request")

// GrantState is the server-derived lifecycle of a grant, as the string facts
// the contract renders. It is Identity & Access's rendering of its own
// record at response time — never an input to any decision, which reads the
// fact fresh at decision time instead (SPEC-0033 AC7).
type GrantState string

const (
	GrantActive  GrantState = "ACTIVE"
	GrantRevoked GrantState = "REVOKED"
	GrantExpired GrantState = "EXPIRED"
)

func grantStateOf(wire identityv1.AuditorGrantState) GrantState {
	switch wire {
	case identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_ACTIVE:
		return GrantActive
	case identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_REVOKED:
		return GrantRevoked
	case identityv1.AuditorGrantState_AUDITOR_GRANT_STATE_EXPIRED:
		return GrantExpired
	default:
		return ""
	}
}

// Grant is one scoped, read-only, time-boxed grant record: scope, state and
// lifecycle only — never pack contents. Identity, state and timestamps are
// server-assigned; a caller supplies scope and requested expiry only
// (SPEC-0033). It carries no repository permission and no renewal-on-use.
type Grant struct {
	GrantID            string
	TenantID           string
	AuditorPrincipalID string
	RangeFrom          time.Time
	RangeTo            time.Time
	RepositoryID       string
	PackIDs            []string
	ExpiresAt          time.Time
	GrantedBy          string
	IssuedAt           time.Time
	RevokedAt          time.Time
	State              GrantState
}

// GrantIssue is the scope an admin requests when issuing a grant, and
// nothing else: the auditor principal, the closed evidence range, an
// optional repository scope, the named packs and the requested expiry. It
// has no field for grant identity, state, versions, or an extension of an
// existing grant — widening a grant is a new decision (SPEC-0033 AC8).
type GrantIssue struct {
	AuditorPrincipalID string
	RangeFrom          time.Time
	RangeTo            time.Time
	RepositoryID       string
	PackIDs            []string
	ExpiresAt          time.Time
}

// ValidateGrantIssue reports whether the issue is one the contract names:
// an auditor principal, a closed range — both bounds present and from not
// after to — at least one named pack, and a requested expiry (SPEC-0033
// AC3: a grant is time-boxed by construction; a grant with no named packs
// authorizes nothing and is rejected at issue time). The HTTP surface uses
// it to refuse a shape the contract does not name before anything reaches
// the backend; IssueGrant enforces the same rule.
func ValidateGrantIssue(in GrantIssue) bool {
	return in.AuditorPrincipalID != "" &&
		!in.RangeFrom.IsZero() && !in.RangeTo.IsZero() && !in.RangeFrom.After(in.RangeTo) &&
		len(in.PackIDs) > 0 && !in.ExpiresAt.IsZero()
}

// Client talks to the backend's AuditorGrantService (Identity & Access).
type Client struct {
	service identityv1.AuditorGrantServiceClient
}

// New wires the adapter onto the generated client.
func New(service identityv1.AuditorGrantServiceClient) *Client {
	return &Client{service: service}
}

// contextOf maps the verified session identity onto the wire context. The
// actor ID and roles are verified server-side; a caller cannot assert them
// (SPEC-0033). The request ID is the idempotency key issuance replays
// against.
func contextOf(read aggregate.ReadContext) *identityv1.AuditorGrantContext {
	return &identityv1.AuditorGrantContext{
		TenantId:   read.TenantID,
		ActorId:    read.ActorID,
		ActorRoles: slices.Clone(read.ActorRoles),
		RequestId:  read.RequestID,
	}
}

// IssueGrant forwards the requested scope to the backend, which decides
// (auditor.grant.manage, owner-only), assigns the grant's identity and
// expiry, and appends the immutable audit record naming the granting admin
// and the auditor principal (SPEC-0033 AC4). The issued grant — server
// state and expiry included — comes back untouched. A shape the contract
// does not name is refused before anything reaches the backend.
func (c *Client) IssueGrant(ctx context.Context, read aggregate.ReadContext, in GrantIssue) (Grant, error) {
	if !ValidateGrantIssue(in) {
		return Grant{}, ErrMalformed
	}
	response, err := c.service.CreateAuditorGrant(ctx, &identityv1.CreateAuditorGrantRequest{
		Context:            contextOf(read),
		AuditorPrincipalId: in.AuditorPrincipalID,
		RangeFrom:          timestamppb.New(in.RangeFrom),
		RangeTo:            timestamppb.New(in.RangeTo),
		RepositoryId:       in.RepositoryID,
		PackIds:            slices.Clone(in.PackIDs),
		ExpiresAt:          timestamppb.New(in.ExpiresAt),
	})
	if err != nil {
		return Grant{}, err
	}
	return shapeGrant(response.GetGrant()), nil
}

// RevokeGrant names the grant to terminate; the backend reads the state
// fresh and the revocation takes effect on the next decision, not the next
// cache cycle (SPEC-0033 AC7). Not-found, cross-tenant, already-revoked,
// expired and unauthorized are the same backend refusal and pass through
// untouched (SPEC-0001).
func (c *Client) RevokeGrant(ctx context.Context, read aggregate.ReadContext, grantID string) (Grant, error) {
	if grantID == "" {
		return Grant{}, ErrMalformed
	}
	response, err := c.service.RevokeAuditorGrant(ctx, &identityv1.RevokeAuditorGrantRequest{
		Context: contextOf(read),
		GrantId: grantID,
	})
	if err != nil {
		return Grant{}, err
	}
	return shapeGrant(response.GetGrant()), nil
}

// ListGrants pages the tenant's grants for administration, optionally
// narrowed to one auditor principal. Scope, state and lifecycle only —
// never pack contents. Listing is a backend decision; a cross-tenant or
// unauthorized list is the same backend refusal as an empty one and passes
// through untouched (SPEC-0001).
func (c *Client) ListGrants(ctx context.Context, read aggregate.ReadContext, auditorPrincipalID string) ([]Grant, error) {
	response, err := c.service.ListAuditorGrants(ctx, &identityv1.ListAuditorGrantsRequest{
		Context:            contextOf(read),
		AuditorPrincipalId: auditorPrincipalID,
	})
	if err != nil {
		return nil, err
	}
	grants := make([]Grant, 0, len(response.GetGrants()))
	for _, grant := range response.GetGrants() {
		grants = append(grants, shapeGrant(grant))
	}
	return grants, nil
}

// shapeGrant renders one wire grant field for field. Timestamps the server
// left unset stay zero; the state is the server's rendering of its own
// record, never an authorization outcome this surface can produce.
func shapeGrant(grant *identityv1.AuditorGrant) Grant {
	shaped := Grant{
		GrantID:            grant.GetGrantId(),
		TenantID:           grant.GetTenantId(),
		AuditorPrincipalID: grant.GetAuditorPrincipalId(),
		RepositoryID:       grant.GetRepositoryId(),
		PackIDs:            slices.Clone(grant.GetPackIds()),
		GrantedBy:          grant.GetGrantedBy(),
		State:              grantStateOf(grant.GetState()),
	}
	if t := grant.GetRangeFrom(); t != nil {
		shaped.RangeFrom = t.AsTime()
	}
	if t := grant.GetRangeTo(); t != nil {
		shaped.RangeTo = t.AsTime()
	}
	if t := grant.GetExpiresAt(); t != nil {
		shaped.ExpiresAt = t.AsTime()
	}
	if t := grant.GetIssuedAt(); t != nil {
		shaped.IssuedAt = t.AsTime()
	}
	if t := grant.GetRevokedAt(); t != nil {
		shaped.RevokedAt = t.AsTime()
	}
	return shaped
}
