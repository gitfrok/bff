package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/security"
)

const mrFindingsTarget = "/api/v1/security/merge-requests/mr-1/findings" +
	"?scanner_class=SAST&severity=HIGH&attribution=ATTRIBUTED&page_size=25&page_token=tok"

// The MR findings page is shaped from the backend's authorized page, filters
// and the opaque merge-request identity forwarded untouched: the BFF shapes,
// it does not attribute, filter or reorder (SPEC-0028 AC9).
func TestMRFindingsShapesPage(t *testing.T) {
	when := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	sec := &stubSecurity{mrPage: security.MergeRequestFindingsPage{
		Findings: []security.MergeRequestFinding{
			{
				Finding: security.Finding{
					FindingID: "finding-b", RepositoryID: "repo-a", ScannerClass: "SAST",
					Severity: "HIGH", Lifecycle: "OPEN", ArtifactPath: "app/main.go",
				},
				Attribution:      "ATTRIBUTED",
				HeadArtifactPath: "app/main.go", HeadEnclosingContent: "func handle",
			},
			{
				Finding:     security.Finding{FindingID: "finding-a", RepositoryID: "repo-a", Severity: "LOW"},
				Triage:      &security.Triage{TriageID: "triage-1", FindingID: "finding-a", State: security.TriageAccept, Justification: "risk owned", Version: 2, ActorID: "actor-a", OccurredAt: when},
				Attribution: "PRE_EXISTING",
			},
		},
		NextPageToken: "next",
		Summary: security.AttributionSummary{
			Status: "ATTRIBUTED", HeadRevision: "head-rev", MergeBaseRevision: "base-rev",
			Stale: true, AttributedHigh: 1,
		},
	}}
	response := serveSecurity(t, NewSecurity(sec, session()), http.MethodGet, mrFindingsTarget, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{
		`"finding_id":"finding-b"`, `"finding_id":"finding-a"`, `"next_page_token":"next"`,
		`"attribution":"ATTRIBUTED"`, `"attribution":"PRE_EXISTING"`,
		`"head_location":{"artifact_path":"app/main.go","enclosing_content":"func handle"`,
		`"triage":{"triage_id":"triage-1"`, `"state":"ACCEPT"`,
		`"summary":{"status":"ATTRIBUTED"`, `"head_revision":"head-rev"`, `"merge_base_revision":"base-rev"`,
		`"stale":true`, `"attributed_high":1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	// A triaged finding renders in its triaged state, not as new (SPEC-0028
	// AC3); an untriaged finding carries no triage field at all.
	if strings.Contains(body, `"triage":{"triage_id":""`) {
		t.Fatalf("body invented a triage for an untriaged finding: %s", body)
	}
	// Order comes from the backend untouched.
	if strings.Index(body, "finding-b") > strings.Index(body, "finding-a") {
		t.Fatalf("order not preserved: %s", body)
	}
	// No count, permission fact or policy outcome travels in the page.
	if strings.Contains(body, "allowed") || strings.Contains(body, "decision_id") || strings.Contains(body, "total_count") {
		t.Fatalf("body leaked a policy outcome or an aggregate: %s", body)
	}
	if sec.mrQuery.MergeRequestID != "mr-1" || sec.mrQuery.ScannerClass != "SAST" ||
		sec.mrQuery.Severity != "HIGH" || sec.mrQuery.Attribution != "ATTRIBUTED" {
		t.Fatalf("query = %+v", sec.mrQuery)
	}
	if sec.mrQuery.PageSize != 25 || sec.mrQuery.PageToken != "tok" {
		t.Fatalf("paging = %+v", sec.mrQuery)
	}
	// Identity came from the session, never from the path or the query.
	if sec.read.TenantID != "tenant-a" || sec.read.ActorID != "actor-a" || sec.read.RequestID == "" {
		t.Fatalf("context = %+v", sec.read)
	}
}

// The empty page is served with its summary intact: an attribution computed
// and found nothing is the only shape that may say "no findings"
// (SPEC-0028 AC7).
func TestMRFindingsEmptyPageShape(t *testing.T) {
	sec := &stubSecurity{mrPage: security.MergeRequestFindingsPage{
		Findings: []security.MergeRequestFinding{},
		Summary:  security.AttributionSummary{Status: "ATTRIBUTED", HeadRevision: "head-rev", MergeBaseRevision: "base-rev"},
	}}
	response := serveSecurity(t, NewSecurity(sec, session()), http.MethodGet, mrFindingsTarget, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := strings.TrimSpace(response.Body.String())
	if body != `{"findings":[],"next_page_token":"","summary":{"status":"ATTRIBUTED","head_revision":"head-rev","merge_base_revision":"base-rev","stale":false,"attributed_low":0,"attributed_medium":0,"attributed_high":0,"attributed_critical":0}}` {
		t.Fatalf("body = %s", body)
	}
}

// A failed, missing or timed-out scan renders as UNAVAILABLE with its
// reason — never as "no findings" (SPEC-0028 AC7).
func TestMRFindingsUnavailableRendersReason(t *testing.T) {
	sec := &stubSecurity{mrPage: security.MergeRequestFindingsPage{
		Findings: []security.MergeRequestFinding{},
		Summary:  security.AttributionSummary{Status: "UNAVAILABLE", UnavailableReason: "HEAD_SCAN_FAILED", HeadRevision: "head-rev"},
	}}
	response := serveSecurity(t, NewSecurity(sec, session()), http.MethodGet, mrFindingsTarget, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{`"status":"UNAVAILABLE"`, `"unavailable_reason":"HEAD_SCAN_FAILED"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
}

// An unnamed filter or an unparsable bound is the same coarse refusal as
// everything else, and none reaches the backend. (An empty merge-request
// segment cannot reach the handler: ServeMux matches {merge_request_id} as
// a non-empty segment and cleans the path otherwise; the adapter refuses an
// empty identity all the same.)
func TestMRFindingsMalformedParamsAreCoarse(t *testing.T) {
	for _, target := range []string{
		"/api/v1/security/merge-requests/mr-1/findings?scanner_class=XRAY",
		"/api/v1/security/merge-requests/mr-1/findings?severity=APOCALYPTIC",
		"/api/v1/security/merge-requests/mr-1/findings?attribution=SOMETIMES",
		"/api/v1/security/merge-requests/mr-1/findings?page_size=many",
	} {
		sec := &stubSecurity{}
		response := serveSecurity(t, NewSecurity(sec, session()), http.MethodGet, target, "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", target, response.Code)
		}
		if sec.calls != 0 {
			t.Fatalf("%s: backend was called for a malformed request", target)
		}
	}
}

// The MR findings surface without a session, and a backend refusal, are the
// same coarse shape: it distinguishes nothing about what exists, what is
// allowed, or why (SPEC-0001).
func TestMRFindingsRefusalsAreCoarse(t *testing.T) {
	sec := &stubSecurity{}
	if response := serveSecurity(t, NewSecurity(sec, stubSession{}), http.MethodGet, mrFindingsTarget, ""); response.Code != http.StatusNotFound {
		t.Fatalf("no session: status = %d, want 404", response.Code)
	}
	if sec.calls != 0 {
		t.Fatal("backend was called without a session")
	}
	refusing := &stubSecurity{err: context.DeadlineExceeded}
	response := serveSecurity(t, NewSecurity(refusing, session()), http.MethodGet, mrFindingsTarget, "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("refusal: status = %d, want 404", response.Code)
	}
	if !strings.Contains(response.Body.String(), "security unavailable") {
		t.Fatalf("body = %s", response.Body.String())
	}
}
