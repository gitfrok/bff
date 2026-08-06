package aggregate

import (
	"context"
	"errors"
	"testing"

	"github.com/gitfrok/bff/internal/pep"
)

type stubPDP struct {
	decision pep.Decision
	err      error
	lastReq  pep.Request
	calls    int
}

func (s *stubPDP) Decide(_ context.Context, req pep.Request) (pep.Decision, error) {
	s.calls++
	s.lastReq = req
	return s.decision, s.err
}

// stubRepos records whether the read happened at all — the assertion that matters most here.
type stubRepos struct {
	calls int
	err   error
}

func (s *stubRepos) Read(_ context.Context, tenantID, repoID string) (RepoView, error) {
	s.calls++
	return RepoView{TenantID: tenantID, RepoID: repoID, Name: "infra"}, s.err
}

func subject() pep.Subject {
	return pep.Subject{ID: "u-1", TenantID: "acme", Roles: []string{"reader"}}
}

// --- SPEC-0002 AC3: a protected action consults the PDP -------------------------------------------

func TestAllowedReadReturnsTheView(t *testing.T) {
	pdp := &stubPDP{decision: pep.Decision{Allowed: true, PolicyRevision: "0.1.0"}}
	repos := &stubRepos{}

	got, err := NewRepos(pdp, repos).Read(context.Background(), subject(), "acme", "repo-1")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.RepoID != "repo-1" || got.Name != "infra" {
		t.Errorf("view = %+v", got)
	}
	if pdp.calls != 1 {
		t.Errorf("PDP consulted %d times, want 1", pdp.calls)
	}
}

func TestDeniedReadReturnsErrDenied(t *testing.T) {
	pdp := &stubPDP{decision: pep.Decision{Allowed: false, Reason: "denied"}}
	repos := &stubRepos{}

	_, err := NewRepos(pdp, repos).Read(context.Background(), subject(), "acme", "repo-1")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
}

// The assertion the whole ordering exists for: a denied read must not have touched the data. If the
// check ran after the fetch, the repository would already have been read — and a fetch that logs,
// meters or caches has effects even when its result is discarded.
func TestDeniedReadNeverTouchesTheData(t *testing.T) {
	repos := &stubRepos{}
	pdp := &stubPDP{decision: pep.Decision{Allowed: false}}

	_, _ = NewRepos(pdp, repos).Read(context.Background(), subject(), "acme", "repo-1")

	if repos.calls != 0 {
		t.Errorf("the repository was read %d times despite a denial", repos.calls)
	}
}

// A broken PDP must not become an unchecked read. This is the failure mode that turns an outage
// into a data breach.
func TestPDPFailureDeniesAndDoesNotRead(t *testing.T) {
	repos := &stubRepos{}
	pdp := &stubPDP{err: errors.New("policy decision unavailable")}

	_, err := NewRepos(pdp, repos).Read(context.Background(), subject(), "acme", "repo-1")

	if !errors.Is(err, ErrDenied) {
		t.Errorf("error = %v, want it to wrap ErrDenied", err)
	}
	if repos.calls != 0 {
		t.Errorf("the repository was read %d times despite no decision", repos.calls)
	}
}

// The question asked must be the question the caller meant. A wrong action or resource type would
// still get an answer — just to something else — which is the failure mode that looks like success.
func TestTheRightQuestionIsAsked(t *testing.T) {
	pdp := &stubPDP{decision: pep.Decision{Allowed: true}}
	if _, err := NewRepos(pdp, &stubRepos{}).Read(context.Background(), subject(), "acme", "repo-1"); err != nil {
		t.Fatalf("Read: %v", err)
	}

	got := pdp.lastReq
	if got.Action != ActionRepoRead {
		t.Errorf("Action = %q, want %q", got.Action, ActionRepoRead)
	}
	if got.Resource.Type != ResourceRepository || got.Resource.ID != "repo-1" {
		t.Errorf("Resource = %+v", got.Resource)
	}
	if got.TenantID != "acme" {
		t.Errorf("TenantID = %q", got.TenantID)
	}
	if got.Subject.ID != "u-1" || got.Subject.TenantID != "acme" {
		t.Errorf("Subject = %+v", got.Subject)
	}
}

// A subject from another tenant is denied by *policy*, not by a check written here — the BFF must
// not be the thing that knows tenants are separate. This asserts the request is passed through
// faithfully so the PDP can see the mismatch and make that call.
func TestCrossTenantSubjectIsPassedToPolicyIntact(t *testing.T) {
	pdp := &stubPDP{decision: pep.Decision{Allowed: false}}
	other := pep.Subject{ID: "u-1", TenantID: "globex", Roles: []string{"reader"}}

	_, err := NewRepos(pdp, &stubRepos{}).Read(context.Background(), other, "acme", "repo-1")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	if pdp.lastReq.Subject.TenantID != "globex" || pdp.lastReq.TenantID != "acme" {
		t.Errorf("the mismatch was not visible to policy: req=%+v", pdp.lastReq)
	}
}

// *pep.PEP satisfies the port this package depends on, so the wiring in cmd/ cannot drift from it.
var _ DecisionPoint = (*pep.PEP)(nil)
