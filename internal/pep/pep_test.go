package pep

import (
	"context"
	"errors"
	"testing"
	"time"

	policyv1 "github.com/gitfrok/bff/gen/proto/policy/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stubPDP counts calls, so "was this served from cache" is observable rather than inferred.
type stubPDP struct {
	resp    *policyv1.DecideResponse
	err     error
	calls   int
	lastReq *policyv1.DecideRequest
}

func (s *stubPDP) Decide(_ context.Context, in *policyv1.DecideRequest, _ ...grpc.CallOption) (*policyv1.DecideResponse, error) {
	s.calls++
	s.lastReq = in
	return s.resp, s.err
}

func allowResp(rev string) *policyv1.DecideResponse {
	return &policyv1.DecideResponse{Allowed: true, Reason: "allowed", PolicyRevision: rev, DecisionId: "01A"}
}

func denyResp(rev string) *policyv1.DecideResponse {
	return &policyv1.DecideResponse{Allowed: false, Reason: "denied", PolicyRevision: rev, DecisionId: "01D"}
}

func req() Request {
	return Request{
		TenantID: "acme",
		Subject:  Subject{ID: "u-1", TenantID: "acme", Roles: []string{"reader"}},
		Action:   "repo.read",
		Resource: Resource{Type: "repository", ID: "repo-1"},
		Context:  map[string]string{"protocol": "https"},
	}
}

// newPEP builds a PEP with a controllable clock so TTL behaviour is deterministic.
func newPEP(t *testing.T, pdp policyv1.PolicyDecisionPointClient) (*PEP, *time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	p := New(pdp, Options{TTL: time.Minute, MaxEntries: 100})
	p.now = func() time.Time { return now }
	return p, &now
}

// --- the decision is the PDP's, unaltered ---------------------------------------------------------

func TestDecisionPassesThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp *policyv1.DecideResponse
		want bool
	}{
		{"allow", allowResp("r1"), true},
		{"deny", denyResp("r1"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newPEP(t, &stubPDP{resp: tc.resp})
			got, err := p.Decide(context.Background(), req())
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if got.Allowed != tc.want {
				t.Errorf("Allowed = %v, want %v", got.Allowed, tc.want)
			}
			if got.PolicyRevision != "r1" {
				t.Errorf("PolicyRevision = %q", got.PolicyRevision)
			}
		})
	}
}

func TestRequestFieldsReachThePDP(t *testing.T) {
	pdp := &stubPDP{resp: allowResp("r1")}
	p, _ := newPEP(t, pdp)
	if _, err := p.Decide(context.Background(), req()); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	got := pdp.lastReq
	if got.GetTenantId() != "acme" || got.GetAction() != "repo.read" ||
		got.GetSubject().GetId() != "u-1" || got.GetResource().GetId() != "repo-1" ||
		got.GetContext()["protocol"] != "https" {
		t.Errorf("PDP saw %+v, want the request's fields", got)
	}
}

// --- AC3: decisions are cached ----------------------------------------------------------------------

func TestRepeatedRequestIsServedFromCache(t *testing.T) {
	pdp := &stubPDP{resp: allowResp("r1")}
	p, _ := newPEP(t, pdp)

	for i := 0; i < 5; i++ {
		if _, err := p.Decide(context.Background(), req()); err != nil {
			t.Fatalf("Decide: %v", err)
		}
	}
	if pdp.calls != 1 {
		t.Errorf("PDP called %d times for 5 identical requests, want 1", pdp.calls)
	}
}

// Denials are cached too. If only allows were, a denied caller could hammer the PDP freely — the
// cheapest denial-of-service against the component every request depends on.
func TestDenialsAreCachedToo(t *testing.T) {
	pdp := &stubPDP{resp: denyResp("r1")}
	p, _ := newPEP(t, pdp)

	for i := 0; i < 3; i++ {
		got, err := p.Decide(context.Background(), req())
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		if got.Allowed {
			t.Fatal("a cached denial came back as an allow")
		}
	}
	if pdp.calls != 1 {
		t.Errorf("PDP called %d times, want 1", pdp.calls)
	}
}

// The cache key must separate every field. A collision here is not a performance bug — it serves
// one subject's decision to another, which is the exact failure authorization exists to prevent.
func TestDifferentRequestsDoNotShareACacheEntry(t *testing.T) {
	base := req()
	variants := map[string]func(*Request){
		"tenant":           func(r *Request) { r.TenantID = "globex" },
		"subject id":       func(r *Request) { r.Subject.ID = "u-2" },
		"subject tenant":   func(r *Request) { r.Subject.TenantID = "globex" },
		"roles":            func(r *Request) { r.Subject.Roles = []string{"owner"} },
		"extra role":       func(r *Request) { r.Subject.Roles = []string{"reader", "owner"} },
		"action":           func(r *Request) { r.Action = "repo.write" },
		"resource type":    func(r *Request) { r.Resource.Type = "merge_request" },
		"resource id":      func(r *Request) { r.Resource.ID = "repo-2" },
		"context value":    func(r *Request) { r.Context = map[string]string{"protocol": "ssh"} },
		"context key":      func(r *Request) { r.Context = map[string]string{"proto": "https"} },
		"extra context":    func(r *Request) { r.Context = map[string]string{"protocol": "https", "ip": "1.2.3.4"} },
		"no context":       func(r *Request) { r.Context = nil },
		"no roles":         func(r *Request) { r.Subject.Roles = nil },
		"empty subject id": func(r *Request) { r.Subject.ID = "" },
	}

	baseKey := cacheKey(base)
	seen := map[string]string{baseKey: "base"}
	for name, mutate := range variants {
		v := req()
		mutate(&v)
		k := cacheKey(v)
		if other, dup := seen[k]; dup {
			t.Errorf("%q and %q share a cache key — one subject's decision would be served to the other", name, other)
		}
		seen[k] = name
	}
}

// Field boundaries must be unambiguous. Without length-prefixed encoding, a subject id of "ab" with
// action "c" and an id of "a" with action "bc" hash the same — the same class of bug the audit
// chain's length prefixes exist to prevent.
func TestCacheKeyFieldBoundariesAreUnambiguous(t *testing.T) {
	a := req()
	a.Subject.ID = "ab"
	a.Action = "c"

	b := req()
	b.Subject.ID = "a"
	b.Action = "bc"

	if cacheKey(a) == cacheKey(b) {
		t.Error("adjacent fields ran together in the cache key")
	}
}

// Go randomises map iteration, so an unsorted context map would make the same request hash
// differently between calls — a cache that never hits, discovered as a latency problem rather
// than as the correctness-adjacent bug it is.
func TestCacheKeyIsStableAcrossMapIterationOrder(t *testing.T) {
	r := req()
	r.Context = map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"}
	first := cacheKey(r)
	for i := 0; i < 50; i++ {
		if got := cacheKey(r); got != first {
			t.Fatal("cache key changed between calls on identical input")
		}
	}
}

// --- invalidation: by revision, not only by clock ---------------------------------------------------

// The property SPEC-0002's open question was resolved to. A policy change is picked up as soon as
// any request observes the new revision, without waiting for TTLs to lapse one by one.
func TestNewPolicyRevisionInvalidatesTheWholeCache(t *testing.T) {
	pdp := &stubPDP{}
	p, _ := newPEP(t, pdp)

	// Two distinct requests, both cached under revision r1.
	other := req()
	other.Resource.ID = "repo-2"
	pdp.resp = allowResp("r1")
	mustDecide(t, p, req())
	mustDecide(t, p, other)
	if pdp.calls != 2 {
		t.Fatalf("setup: PDP called %d times, want 2", pdp.calls)
	}

	// Both are now cached: no further calls.
	mustDecide(t, p, req())
	mustDecide(t, p, other)
	if pdp.calls != 2 {
		t.Fatalf("cached requests still called the PDP (%d calls)", pdp.calls)
	}

	// A third request observes a new revision. That must drop everything cached under r1 —
	// including `other`, which nobody asked about again.
	third := req()
	third.Resource.ID = "repo-3"
	pdp.resp = allowResp("r2")
	mustDecide(t, p, third)

	before := pdp.calls
	mustDecide(t, p, other)
	if pdp.calls != before+1 {
		t.Error("a decision cached under the old revision survived a policy change; a tightened " +
			"rule would not apply until its TTL happened to lapse")
	}
}

func TestEntriesExpireAfterTTL(t *testing.T) {
	pdp := &stubPDP{resp: allowResp("r1")}
	p, now := newPEP(t, pdp)

	mustDecide(t, p, req())
	mustDecide(t, p, req())
	if pdp.calls != 1 {
		t.Fatalf("setup: %d calls", pdp.calls)
	}

	*now = now.Add(61 * time.Second)
	mustDecide(t, p, req())
	if pdp.calls != 2 {
		t.Error("an expired entry was served; TTL bounds how stale a subject's roles may be")
	}
}

// --- failures are never cached, and never allow ------------------------------------------------------

// A transport failure is the absence of a decision. Caching it would store an answer no policy gave
// and keep denying after the PDP recovered.
func TestTransportFailureIsNotCached(t *testing.T) {
	pdp := &stubPDP{err: status.Error(codes.Internal, "policy decision unavailable")}
	p, _ := newPEP(t, pdp)

	got, err := p.Decide(context.Background(), req())
	if err == nil {
		t.Fatal("a transport failure returned no error")
	}
	if got.Allowed {
		t.Fatal("a transport failure returned Allowed=true")
	}

	// Recovery must be immediate, not TTL-delayed.
	pdp.err = nil
	pdp.resp = allowResp("r1")
	got, err = p.Decide(context.Background(), req())
	if err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if !got.Allowed {
		t.Error("the failure was cached: the PEP kept denying after the PDP recovered")
	}
}

func TestAllowedIsNeverTrueOnError(t *testing.T) {
	p, _ := newPEP(t, &stubPDP{err: errors.New("connection refused")})
	got, err := p.Decide(context.Background(), req())
	if err == nil {
		t.Fatal("expected an error")
	}
	if got.Allowed {
		t.Error("Allowed=true alongside an error")
	}
}

// --- the cache is bounded --------------------------------------------------------------------------

// An unbounded cache keyed by request is a memory exhaustion vector: an attacker varies the
// resource id and grows it without limit, in the component every request passes through.
func TestCacheIsBounded(t *testing.T) {
	pdp := &stubPDP{resp: allowResp("r1")}
	p := New(pdp, Options{TTL: time.Hour, MaxEntries: 10})
	p.now = func() time.Time { return time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC) }

	for i := 0; i < 500; i++ {
		r := req()
		r.Resource.ID = "repo-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		mustDecide(t, p, r)
	}
	if got := p.Len(); got > 10 {
		t.Errorf("cache holds %d entries, want at most 10", got)
	}
}

// Eviction must never resurrect a decision under a changed policy or past its TTL. Whatever is
// evicted, what remains must still be correct.
func TestEvictionPrefersExpiredEntries(t *testing.T) {
	pdp := &stubPDP{resp: allowResp("r1")}
	p := New(pdp, Options{TTL: time.Minute, MaxEntries: 4})
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }

	for i := 0; i < 4; i++ {
		r := req()
		r.Resource.ID = "old-" + string(rune('a'+i))
		mustDecide(t, p, r)
	}
	now = now.Add(2 * time.Minute) // everything above is now stale

	fresh := req()
	fresh.Resource.ID = "fresh"
	mustDecide(t, p, fresh)

	if p.Len() > 4 {
		t.Errorf("cache holds %d entries, want at most 4", p.Len())
	}
	// The fresh entry must be the one that survived.
	before := pdp.calls
	mustDecide(t, p, fresh)
	if pdp.calls != before {
		t.Error("the freshly-inserted entry was evicted in favour of expired ones")
	}
}

func mustDecide(t *testing.T, p *PEP, r Request) Decision {
	t.Helper()
	got, err := p.Decide(context.Background(), r)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	return got
}
