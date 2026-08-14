package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/security"
)

// stubSecurity records the identity and filters it was handed and answers
// with canned dashboard shapes.
type stubSecurity struct {
	read       aggregate.ReadContext
	triage     security.TriageRequest
	triageOut  security.Triage
	filters    security.Filters
	pageSize   int32
	pageToken  string
	dimensions []string
	page       security.FindingPage
	summary    security.Summary
	mrQuery    security.MergeRequestFindingsQuery
	mrPage     security.MergeRequestFindingsPage
	err        error
	calls      int
}

func (s *stubSecurity) ListFindings(_ context.Context, read aggregate.ReadContext, f security.Filters, pageSize int32, pageToken string) (security.FindingPage, error) {
	s.read, s.filters, s.pageSize, s.pageToken, s.calls = read, f, pageSize, pageToken, s.calls+1
	return s.page, s.err
}

func (s *stubSecurity) FindingsSummary(_ context.Context, read aggregate.ReadContext, f security.Filters, dimensions []string) (security.Summary, error) {
	s.read, s.filters, s.dimensions, s.calls = read, f, dimensions, s.calls+1
	return s.summary, s.err
}

func (s *stubSecurity) SetTriage(_ context.Context, read aggregate.ReadContext, in security.TriageRequest) (security.Triage, error) {
	s.read, s.triage, s.calls = read, in, s.calls+1
	return s.triageOut, s.err
}

func (s *stubSecurity) ListMergeRequestFindings(_ context.Context, read aggregate.ReadContext, q security.MergeRequestFindingsQuery) (security.MergeRequestFindingsPage, error) {
	s.read, s.mrQuery, s.calls = read, q, s.calls+1
	return s.mrPage, s.err
}

func serveSecurity(t *testing.T, h *SecurityHandler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	h.Routes().ServeHTTP(recorder, httptest.NewRequest(method, target, strings.NewReader(body)))
	return recorder
}

const triageBody = `{"finding_id":"finding-a","state":"ACCEPT","justification":"risk owned","expected_version":2}`

// A triage decision is forwarded under the session's verified identity and
// answered with the record now in force: no count, no permission fact, no
// policy outcome.
func TestTriageShapesRecord(t *testing.T) {
	when := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	sec := &stubSecurity{triageOut: security.Triage{
		TriageID: "triage-1", FindingID: "finding-a", RepositoryID: "repo-a",
		State: security.TriageAccept, Justification: "risk owned",
		Version: 3, ActorID: "actor-a", OccurredAt: when,
	}}
	response := serveSecurity(t, NewSecurity(sec, session()), http.MethodPost, "/api/v1/security/triage", triageBody)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{`"triage_id":"triage-1"`, `"finding_id":"finding-a"`, `"state":"ACCEPT"`, `"version":3`, `"actor_id":"actor-a"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, "allowed") || strings.Contains(body, "decision_id") || strings.Contains(body, "total") {
		t.Fatalf("body leaked a policy outcome or an aggregate: %s", body)
	}
	if sec.triage.FindingID != "finding-a" || sec.triage.State != security.TriageAccept ||
		sec.triage.Justification != "risk owned" || sec.triage.ExpectedVersion != 2 {
		t.Fatalf("triage request = %+v", sec.triage)
	}
	// Identity came from the session, never from the body.
	if sec.read.TenantID != "tenant-a" || sec.read.ActorID != "actor-a" || sec.read.RequestID == "" {
		t.Fatalf("triage context = %+v", sec.read)
	}
}

// A request without a session is refused and never reaches the backend.
func TestTriageWithoutSessionIsRefused(t *testing.T) {
	sec := &stubSecurity{}
	response := serveSecurity(t, NewSecurity(sec, stubSession{}), http.MethodPost, "/api/v1/security/triage", triageBody)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if sec.calls != 0 {
		t.Fatal("backend was called without a session")
	}
}

// A malformed body and an unnamed decision are the same coarse refusal as
// everything else, and neither reaches the backend (SPEC-0026 AC5).
func TestTriageMalformedInputIsCoarse(t *testing.T) {
	for _, body := range []string{
		`{not json`,
		`{"finding_id":"finding-a","state":"CLOSED"}`,
		`{"finding_id":"finding-a"}`,
	} {
		sec := &stubSecurity{}
		response := serveSecurity(t, NewSecurity(sec, session()), http.MethodPost, "/api/v1/security/triage", body)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", body, response.Code)
		}
		if sec.calls != 0 {
			t.Fatalf("%s: backend was called for a malformed request", body)
		}
	}
}

// A backend refusal is the one coarse denial; it says nothing about what
// exists or why (SPEC-0001).
func TestTriageBackendRefusalIsCoarse(t *testing.T) {
	sec := &stubSecurity{err: context.DeadlineExceeded}
	response := serveSecurity(t, NewSecurity(sec, session()), http.MethodPost, "/api/v1/security/triage", triageBody)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if !strings.Contains(response.Body.String(), "security unavailable") {
		t.Fatalf("body = %s", response.Body.String())
	}
}

const dashboardTarget = "/api/v1/security/dashboard?repository=repo-a&scanner_class=SAST&severity=HIGH" +
	"&lifecycle=OPEN&min_age_days=3&max_age_days=30&owning_team=team-a&page_size=25&page_token=tok"

// The dashboard is answered with the backend's authorized page, filters
// forwarded untouched: the BFF shapes, it does not filter or reorder.
func TestDashboardShapesFindings(t *testing.T) {
	sec := &stubSecurity{page: security.FindingPage{
		Findings: []security.Finding{
			{FindingID: "finding-b", RepositoryID: "repo-b", Severity: "HIGH"},
			{FindingID: "finding-a", RepositoryID: "repo-a", Severity: "CRITICAL"},
		},
		NextPageToken: "next",
	}}
	response := serveSecurity(t, NewSecurity(sec, session()), http.MethodGet, dashboardTarget, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{`"finding-b"`, `"finding-a"`, `"next_page_token":"next"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	// Order comes from the backend untouched.
	if strings.Index(body, "finding-b") > strings.Index(body, "finding-a") {
		t.Fatalf("order not preserved: %s", body)
	}
	if sec.filters.Repository != "repo-a" || sec.filters.ScannerClass != "SAST" || sec.filters.Severity != "HIGH" ||
		sec.filters.Lifecycle != "OPEN" || sec.filters.MinAgeDays != 3 || sec.filters.MaxAgeDays != 30 ||
		sec.filters.OwningTeam != "team-a" {
		t.Fatalf("filters = %+v", sec.filters)
	}
	if sec.pageSize != 25 || sec.pageToken != "tok" {
		t.Fatalf("paging = %d %q", sec.pageSize, sec.pageToken)
	}
	if sec.read.TenantID != "tenant-a" || sec.read.ActorID != "actor-a" || sec.read.RequestID == "" {
		t.Fatalf("context = %+v", sec.read)
	}
}

// The empty page is the one shape a no-match query and an unauthorized-only
// query both return: findings present and empty, no distinguishing field
// (SPEC-0026 AC6).
func TestDashboardEmptyPageShape(t *testing.T) {
	sec := &stubSecurity{page: security.FindingPage{Findings: []security.Finding{}}}
	response := serveSecurity(t, NewSecurity(sec, session()), http.MethodGet, "/api/v1/security/dashboard", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := strings.TrimSpace(response.Body.String())
	if body != `{"findings":[],"next_page_token":""}` {
		t.Fatalf("body = %s", body)
	}
	// An absent filter is the org-wide read: nothing crossed the wire but
	// the identity (SPEC-0026 AC1).
	if sec.filters != (security.Filters{}) {
		t.Fatalf("filters = %+v", sec.filters)
	}
}

// An unnamed filter or an unparsable bound is the same coarse refusal as
// everything else, and neither reaches the backend.
func TestDashboardMalformedParamsAreCoarse(t *testing.T) {
	for _, target := range []string{
		"/api/v1/security/dashboard?scanner_class=XRAY",
		"/api/v1/security/dashboard?severity=APOCALYPTIC",
		"/api/v1/security/dashboard?page_size=many",
		"/api/v1/security/dashboard?min_age_days=soon",
	} {
		sec := &stubSecurity{page: security.FindingPage{Findings: []security.Finding{}}}
		response := serveSecurity(t, NewSecurity(sec, session()), http.MethodGet, target, "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", target, response.Code)
		}
		if sec.calls != 0 {
			t.Fatalf("%s: backend was called for a malformed request", target)
		}
	}
}

// The dashboard without a session, and a dashboard refusal, are the same
// coarse shape.
func TestDashboardRefusalsAreCoarse(t *testing.T) {
	sec := &stubSecurity{}
	if response := serveSecurity(t, NewSecurity(sec, stubSession{}), http.MethodGet, "/api/v1/security/dashboard", ""); response.Code != http.StatusNotFound {
		t.Fatalf("no session: status = %d, want 404", response.Code)
	}
	if sec.calls != 0 {
		t.Fatal("backend was called without a session")
	}
	refusing := &stubSecurity{err: context.DeadlineExceeded}
	if response := serveSecurity(t, NewSecurity(refusing, session()), http.MethodGet, "/api/v1/security/dashboard", ""); response.Code != http.StatusNotFound {
		t.Fatalf("refusal: status = %d, want 404", response.Code)
	}
}

// The summary is shaped from the backend's authorized counts and facets:
// which values appear is the backend's decision, and the BFF forwards the
// requested dimensions untouched.
func TestSummaryShapesFacets(t *testing.T) {
	sec := &stubSecurity{summary: security.Summary{
		TotalCount: 7,
		Facets: []security.Facet{{
			Dimension: "severity",
			Values:    []security.FacetValue{{Value: "HIGH", Count: 4}, {Value: "CRITICAL", Count: 3}},
		}},
	}}
	response := serveSecurity(t, NewSecurity(sec, session()), http.MethodGet,
		"/api/v1/security/findings/summary?repository=repo-a&facet=severity&facet=owning_team", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{`"total_count":7`, `"dimension":"severity"`, `"value":"HIGH"`, `"count":4`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	if sec.filters.Repository != "repo-a" {
		t.Fatalf("filters = %+v", sec.filters)
	}
	if len(sec.dimensions) != 2 || sec.dimensions[0] != "severity" || sec.dimensions[1] != "owning_team" {
		t.Fatalf("dimensions = %v", sec.dimensions)
	}
	if sec.read.TenantID != "tenant-a" || sec.read.ActorID != "actor-a" || sec.read.RequestID == "" {
		t.Fatalf("context = %+v", sec.read)
	}
}

// A summary without a session, and a summary refusal, are the same coarse
// shape: an unauthorized total has no shape to travel in (SPEC-0027 AC4).
func TestSummaryRefusalsAreCoarse(t *testing.T) {
	sec := &stubSecurity{}
	if response := serveSecurity(t, NewSecurity(sec, stubSession{}), http.MethodGet, "/api/v1/security/findings/summary", ""); response.Code != http.StatusNotFound {
		t.Fatalf("no session: status = %d, want 404", response.Code)
	}
	if sec.calls != 0 {
		t.Fatal("backend was called without a session")
	}
	refusing := &stubSecurity{err: context.DeadlineExceeded}
	if response := serveSecurity(t, NewSecurity(refusing, session()), http.MethodGet, "/api/v1/security/findings/summary?scanner_class=XRAY", ""); response.Code != http.StatusNotFound {
		t.Fatalf("refusal: status = %d, want 404", response.Code)
	}
}
