// Package pep is the BFF's Policy Enforcement Point: it asks the PDP and caches the answers.
//
// It decides nothing. Every question goes to the PDP over contracts/proto/policy/v1 and the answer
// is returned unaltered — invariant 2, and invariant 18's "no business logic in the BFF" applies
// with particular force to authorization. What lives here is the *calling* of the PDP and the
// caching of its replies, which is transport concern, not policy.
//
// WHY THE CACHE IS HERE and not in the backend's PDP: this is where the network round-trip is.
// ADR-0006 accepts a PDP call per request and names decision caching as the mitigation, and the
// hop worth eliminating is the gRPC one. The backend's evaluator prepares its Rego query once, so
// its own cost is microseconds; the millisecond is the wire.
//
// SPEC-0002 AC3, T-0005.
package pep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	policyv1 "github.com/gitfrok/bff/gen/proto/policy/v1"
)

// Subject, Resource, Request and Decision mirror contracts/proto/policy/v1. They exist as plain
// structs so callers in this repo are not writing protobuf types into their signatures, which
// would make the generated code part of every aggregator's surface.
type Subject struct {
	ID       string
	TenantID string
	Roles    []string
}

// Resource is what the action would be performed on.
type Resource struct {
	Type string
	ID   string
}

// Request asks whether one action is permitted.
type Request struct {
	TenantID string
	Subject  Subject
	Action   string
	Resource Resource
	Context  map[string]string
}

// Decision is the PDP's answer. Allowed's zero value is false, so a Decision that was never
// populated denies.
type Decision struct {
	Allowed        bool
	Reason         string
	PolicyRevision string
	DecisionID     string
}

// Options configures the cache.
type Options struct {
	// TTL bounds how long a decision may be reused.
	//
	// It exists for staleness the *policy revision* cannot detect: a subject's roles can change
	// while the policy does not, and nothing in the response would reveal it. Revision-flushing
	// handles policy changes; the TTL handles input changes. Keep it short — this is the window in
	// which a revoked role still works.
	TTL time.Duration
	// MaxEntries bounds the cache. An unbounded map keyed by request is a memory-exhaustion
	// vector: vary the resource id and it grows without limit, in the one component every
	// request passes through.
	MaxEntries int
}

const (
	defaultTTL        = 30 * time.Second
	defaultMaxEntries = 10_000
)

type entry struct {
	decision  Decision
	expiresAt time.Time
}

// PEP calls the PDP and caches its decisions.
type PEP struct {
	pdp  policyv1.PolicyDecisionPointClient
	opts Options

	mu sync.Mutex
	// entries is guarded by mu. A plain map plus a mutex rather than sync.Map because the
	// revision flush below is a whole-map operation, which sync.Map does not do well.
	entries map[string]entry
	// revision is the bundle revision every cached entry was computed under. When a fresh
	// response reports a different one, everything here was decided under superseded rules.
	revision string

	// now is injectable so TTL behaviour is testable without sleeping.
	now func() time.Time
}

// New returns a PEP calling pdp.
func New(pdp policyv1.PolicyDecisionPointClient, opts Options) *PEP {
	if opts.TTL <= 0 {
		opts.TTL = defaultTTL
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = defaultMaxEntries
	}
	return &PEP{
		pdp:     pdp,
		opts:    opts,
		entries: make(map[string]entry),
		now:     time.Now,
	}
}

// Decide answers whether req is permitted, from cache when possible.
//
// On any error the returned Decision is the zero value, so a caller that ignores the error still
// denies. Failures are never cached: a transport failure is the absence of a decision, and storing
// it would keep denying after the PDP recovered — while also recording an answer no policy gave.
func (p *PEP) Decide(ctx context.Context, req Request) (Decision, error) {
	key := cacheKey(req)
	if d, ok := p.lookup(key); ok {
		return d, nil
	}

	resp, err := p.pdp.Decide(ctx, &policyv1.DecideRequest{
		TenantId: req.TenantID,
		Subject: &policyv1.Subject{
			Id:       req.Subject.ID,
			TenantId: req.Subject.TenantID,
			Roles:    req.Subject.Roles,
		},
		Action: req.Action,
		Resource: &policyv1.Resource{
			Type: req.Resource.Type,
			Id:   req.Resource.ID,
		},
		Context: req.Context,
	})
	if err != nil {
		return Decision{}, fmt.Errorf("pep: deciding %s: %w", req.Action, err)
	}

	decision := Decision{
		Allowed:        resp.GetAllowed(),
		Reason:         resp.GetReason(),
		PolicyRevision: resp.GetPolicyRevision(),
		DecisionID:     resp.GetDecisionId(),
	}
	// Denials are stored alongside allows. Caching only allows would leave a denied caller free to
	// hammer the PDP — the cheapest denial-of-service against the component every request needs.
	p.store(key, decision)
	return decision, nil
}

// Len reports how many decisions are cached. For tests and, later, a metric.
func (p *PEP) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

func (p *PEP) lookup(key string) (Decision, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	e, ok := p.entries[key]
	if !ok {
		return Decision{}, false
	}
	if !p.now().Before(e.expiresAt) {
		delete(p.entries, key)
		return Decision{}, false
	}
	return e.decision, true
}

// store caches a decision, flushing everything first if the policy moved on.
//
// This is the invalidation SPEC-0002's open question resolved to: by revision, not by clock. The
// limit is worth stating plainly — a policy change is picked up the moment *any* request reaches
// the PDP and observes the new revision, so between the change and that first miss, cached entries
// still serve the old rules. The TTL is what guarantees that first miss happens.
func (p *PEP) store(key string, d Decision) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if d.PolicyRevision != p.revision {
		// Every entry here was decided under rules that no longer apply.
		p.entries = make(map[string]entry, len(p.entries))
		p.revision = d.PolicyRevision
	}

	now := p.now()
	if len(p.entries) >= p.opts.MaxEntries {
		p.evictLocked(now)
	}

	p.entries[key] = entry{decision: d, expiresAt: now.Add(p.opts.TTL)}
}

// evictLocked makes room. Expired entries go first — they are free, being already invalid. If none
// are expired, it drops an arbitrary live entry: Go's map iteration order gives random replacement,
// which needs no per-entry bookkeeping and cannot be gamed by an attacker shaping an access
// pattern the way LRU can. The cost of a wrong eviction is one extra PDP call, never a wrong answer.
func (p *PEP) evictLocked(now time.Time) {
	for k, e := range p.entries {
		if !now.Before(e.expiresAt) {
			delete(p.entries, k)
		}
	}
	for len(p.entries) >= p.opts.MaxEntries {
		for k := range p.entries {
			delete(p.entries, k)
			break
		}
	}
}

// cacheKey derives a stable key covering every field of the request.
//
// A collision here serves one subject's decision to another, so this is a correctness mechanism
// wearing a performance mechanism's clothes. Two properties make it safe:
//
// Every value is length-prefixed, so adjacent fields cannot run together — without it, subject
// "ab" with action "c" and subject "a" with action "bc" produce the same digest. The audit chain
// in the backend length-prefixes for exactly this reason.
//
// Roles are hashed in the order given, NOT sorted. Sorting would raise the hit rate and would be
// safe only if no policy ever depended on role order — an assumption about rules this repo does
// not own and cannot see. Context keys are sorted because a Go map has no order to preserve and
// randomised iteration would otherwise make an identical request hash differently every call.
func cacheKey(req Request) string {
	h := sha256.New()
	write := func(s string) {
		fmt.Fprintf(h, "%d:%s", len(s), s)
	}

	write(req.TenantID)
	write(req.Subject.ID)
	write(req.Subject.TenantID)
	write(strconv.Itoa(len(req.Subject.Roles)))
	for _, r := range req.Subject.Roles {
		write(r)
	}
	write(req.Action)
	write(req.Resource.Type)
	write(req.Resource.ID)

	keys := make([]string, 0, len(req.Context))
	for k := range req.Context {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	write(strconv.Itoa(len(keys)))
	for _, k := range keys {
		write(k)
		write(req.Context[k])
	}

	return hex.EncodeToString(h.Sum(nil))
}
