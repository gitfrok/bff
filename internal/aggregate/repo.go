// Package aggregate shapes backend data for the web frontend. It holds no business logic
// (invariant 18): it calls, it composes, it shapes.
//
// It is also where the PEP is *used*, which is the half of SPEC-0002 AC3 that the pep package alone
// does not demonstrate: a protected action that consults the PDP before doing anything.
package aggregate

import (
	"context"
	"errors"
	"fmt"

	"github.com/gitfrok/bff/internal/pep"
)

// ActionRepoRead is the sample protected action T-0005 wires end to end.
//
// It is the one the Repository context and Phase-1's T-0014 will actually ask about, so the policy
// behind it outlives the skeleton — as opposed to a destructive verb nothing performs yet, which
// would make this a stub guarding nothing.
const ActionRepoRead = "repo.read"

// ResourceRepository is the resource type the policy pins repo.* actions to.
const ResourceRepository = "repository"

// ErrDenied is returned when policy refuses the action. Callers map it to 403.
//
// It carries no detail about *why*. The PDP's reason is already coarse by design, and a BFF that
// elaborated on it would rebuild the oracle that coarseness closes — this is the layer closest to
// an untrusted caller, so it is the worst place to be helpful.
var ErrDenied = errors.New("aggregate: denied by policy")

// RepoView is the shaped repository representation the frontend consumes.
type RepoView struct {
	TenantID string
	RepoID   string
	Name     string
}

// RepoReader fetches repository data. Backed by a gRPC client to the Repository context once
// T-0014 lands; a port here so this package is testable and so the BFF never names a backend type.
type RepoReader interface {
	Read(ctx context.Context, tenantID, repoID string) (RepoView, error)
}

// DecisionPoint is the authorization port — satisfied by *pep.PEP.
type DecisionPoint interface {
	Decide(ctx context.Context, req pep.Request) (pep.Decision, error)
}

// Repos aggregates repository reads behind a policy check.
type Repos struct {
	pdp   DecisionPoint
	repos RepoReader
}

// NewRepos wires the aggregator.
func NewRepos(pdp DecisionPoint, repos RepoReader) *Repos {
	return &Repos{pdp: pdp, repos: repos}
}

// Read returns a repository the subject is permitted to see.
//
// ORDER MATTERS AND IS THE POINT: the decision is obtained *before* the read, not after. Checking
// afterwards would mean the data was already fetched — and in a system where the fetch is a gRPC
// call that may itself log, cache or meter, "we fetched it but did not return it" is not the same
// as not having read it. The failure paths are equally deliberate: a decision error returns before
// any read, so a broken PDP cannot become an unchecked read.
func (r *Repos) Read(ctx context.Context, subject pep.Subject, tenantID, repoID string) (RepoView, error) {
	decision, err := r.pdp.Decide(ctx, pep.Request{
		TenantID: tenantID,
		Subject:  subject,
		Action:   ActionRepoRead,
		Resource: pep.Resource{Type: ResourceRepository, ID: repoID},
	})
	if err != nil {
		// No decision was reached. Deny — api/pep both say an error is a refusal, and the
		// alternative is reading data nobody authorised.
		return RepoView{}, fmt.Errorf("%w: %w", ErrDenied, err)
	}
	if !decision.Allowed {
		return RepoView{}, ErrDenied
	}

	return r.repos.Read(ctx, tenantID, repoID)
}
