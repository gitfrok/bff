package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/handlers"
	"github.com/gitfrok/bff/internal/policyview"
)

// SPEC-0055 AC2/AC3: reads only, one coarse refusal, and a surface with no
// authoring verb anywhere on it.

type fakePolicy struct {
	bundle  policyview.BundleStatus
	record  policyview.DecisionRecord
	err     error
	gotID   string
	gotRead aggregate.ReadContext
}

func (f *fakePolicy) BundleStatus(_ context.Context, read aggregate.ReadContext) (policyview.BundleStatus, error) {
	f.gotRead = read
	return f.bundle, f.err
}

func (f *fakePolicy) Decision(_ context.Context, read aggregate.ReadContext, id string) (policyview.DecisionRecord, error) {
	f.gotRead, f.gotID = read, id
	return f.record, f.err
}

func policySession() fakeSession {
	return fakeSession{read: aggregate.ReadContext{TenantID: "t-1", ActorID: "a-1"}, ok: true}
}

func servePolicy(t *testing.T, p handlers.PolicyReads, session handlers.Session, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handlers.NewPolicy(p, session).ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestBundleStatusIsShapedAndForwarded(t *testing.T) {
	p := &fakePolicy{bundle: policyview.BundleStatus{BundleRevision: "0.10.0", LoadedAt: "2026-08-19T09:00:00Z"}}
	rec := servePolicy(t, p, policySession(), http.MethodGet, "/api/v1/policy/bundle")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var view handlers.BundleStatusView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.BundleRevision != "0.10.0" {
		t.Fatalf("shaped %+v", view)
	}
	if p.gotRead.RequestID == "" {
		t.Fatal("a request id must be minted here")
	}
}

func TestADecisionRecordCarriesWhatDecidedIt(t *testing.T) {
	p := &fakePolicy{record: policyview.DecisionRecord{
		DecisionID: "d-1", Action: "repo.read", ResourceType: "repository", ResourceID: "repo-1",
		Allowed: false, PolicyRevision: "0.10.0", InputDigest: "sha256:abc",
		Mode: "EVALUATION_MODE_ENFORCE", DecidedAt: "2026-08-19T09:00:00Z",
	}}
	rec := servePolicy(t, p, policySession(), http.MethodGet, "/api/v1/policy/decisions/d-1")

	var view handlers.DecisionRecordView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// PR-16's "the deciding policy version is recorded on the decision",
	// reachable for the first time.
	if view.PolicyRevision != "0.10.0" || view.InputDigest != "sha256:abc" {
		t.Fatalf("shaped %+v", view)
	}
	if p.gotID != "d-1" {
		t.Fatalf("forwarded %q", p.gotID)
	}
}

// ADR-0073's deferral at the layer a browser reads: this surface exposes no
// verb that writes, and no route that would accept a policy.
func TestTheSurfaceExposesNoAuthoringRoute(t *testing.T) {
	for _, target := range []string{"/api/v1/policy/bundle", "/api/v1/policy/decisions/d-1"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			rec := servePolicy(t, &fakePolicy{}, policySession(), method, target)
			if rec.Code == http.StatusOK {
				t.Fatalf("%s %s was served — this surface writes nothing", method, target)
			}
		}
	}
}

func TestPolicyReadsRefuseWithoutASession(t *testing.T) {
	for _, target := range []string{"/api/v1/policy/bundle", "/api/v1/policy/decisions/d-1"} {
		if rec := servePolicy(t, &fakePolicy{}, fakeSession{ok: false}, http.MethodGet, target); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d", target, rec.Code)
		}
	}
}

// A decision that does not exist and one belonging to another tenant must be
// the same answer, which is what keeps a probe from enumerating either.
func TestAnUnreadableDecisionIsTheOneCoarseRefusal(t *testing.T) {
	rec := servePolicy(t, &fakePolicy{err: errors.New("not found")}, policySession(),
		http.MethodGet, "/api/v1/policy/decisions/d-1")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
	if body := rec.Body.String(); body != "policy unavailable\n" {
		t.Fatalf("the refusal names a cause: %q", body)
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "tenant") {
		t.Fatal("the refusal distinguishes cross-tenant from absent")
	}
}

func TestTheBundleResponseCarriesNoPolicySource(t *testing.T) {
	rec := servePolicy(t, &fakePolicy{bundle: policyview.BundleStatus{BundleRevision: "0.10.0"}},
		policySession(), http.MethodGet, "/api/v1/policy/bundle")
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for key := range raw {
		if key != "bundle_revision" && key != "loaded_at" {
			t.Fatalf("the response carries %q — the bundle's contents are not a tenant read", key)
		}
	}
}
