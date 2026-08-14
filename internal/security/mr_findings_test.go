package security

import (
	"context"
	"errors"
	"testing"

	securityv1 "github.com/gitfrok/bff/gen/proto/security/v1"
)

func mrQuery() MergeRequestFindingsQuery {
	return MergeRequestFindingsQuery{
		MergeRequestID: "mr-1", ScannerClass: "SAST", Severity: "HIGH",
		Attribution: "ATTRIBUTED", PageSize: 25, PageToken: "tok",
	}
}

// The wire request carries exactly the session's verified identity and the
// opaque merge-request identity: no head revision, no merge base, no
// attribution claim and no authorization outcome — the contract has no field
// for any of them (SPEC-0028).
func TestListMergeRequestFindingsForwardsIdentityOnly(t *testing.T) {
	f := &fakeService{mrFindResp: &securityv1.ListMergeRequestFindingsResponse{}}
	_, err := New(f).ListMergeRequestFindings(context.Background(), read(), mrQuery())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	req := f.mrFindReq
	ctx := req.GetContext()
	if ctx.GetTenantId() != "tenant-a" || ctx.GetActorId() != "actor-a" || ctx.GetRequestId() != "request-a" {
		t.Fatalf("context = %v", ctx)
	}
	//arch:allow-inline-authz this compares a forwarded role string for equality in a test; it grants nothing
	if len(ctx.GetActorRoles()) != 1 || ctx.GetActorRoles()[0] != "member" {
		t.Fatalf("roles = %v", ctx.GetActorRoles())
	}
	if req.GetMergeRequestId() != "mr-1" {
		t.Fatalf("merge_request_id = %q", req.GetMergeRequestId())
	}
	if req.GetScannerClassFilter() != securityv1.ScannerClass_SCANNER_CLASS_SAST ||
		req.GetSeverityFilter() != securityv1.FindingSeverity_FINDING_SEVERITY_HIGH ||
		req.GetAttributionFilter() != securityv1.AttributionStatus_ATTRIBUTION_STATUS_ATTRIBUTED {
		t.Fatalf("filters = %v", req)
	}
	if req.GetPageSize() != 25 || req.GetPageToken() != "tok" {
		t.Fatalf("paging = %v", req)
	}
}

// An empty filter set is the unfiltered read of one merge request: every
// filter field crosses the wire as its UNSPECIFIED/empty/zero value.
func TestListMergeRequestFindingsEmptyFiltersAreUnfiltered(t *testing.T) {
	f := &fakeService{mrFindResp: &securityv1.ListMergeRequestFindingsResponse{}}
	if _, err := New(f).ListMergeRequestFindings(context.Background(), read(),
		MergeRequestFindingsQuery{MergeRequestID: "mr-1"}); err != nil {
		t.Fatalf("err = %v", err)
	}
	req := f.mrFindReq
	if req.GetScannerClassFilter() != securityv1.ScannerClass_SCANNER_CLASS_UNSPECIFIED ||
		req.GetSeverityFilter() != securityv1.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED ||
		req.GetAttributionFilter() != securityv1.AttributionStatus_ATTRIBUTION_STATUS_UNSPECIFIED ||
		req.GetPageSize() != 0 || req.GetPageToken() != "" {
		t.Fatalf("filters = %v", req)
	}
}

// Every named attribution maps onto its contract enum.
func TestListMergeRequestFindingsAttributionFilters(t *testing.T) {
	for name, want := range map[string]securityv1.AttributionStatus{
		"ATTRIBUTED":   securityv1.AttributionStatus_ATTRIBUTION_STATUS_ATTRIBUTED,
		"PRE_EXISTING": securityv1.AttributionStatus_ATTRIBUTION_STATUS_PRE_EXISTING,
		"UNAVAILABLE":  securityv1.AttributionStatus_ATTRIBUTION_STATUS_UNAVAILABLE,
	} {
		f := &fakeService{mrFindResp: &securityv1.ListMergeRequestFindingsResponse{}}
		if _, err := New(f).ListMergeRequestFindings(context.Background(), read(),
			MergeRequestFindingsQuery{MergeRequestID: "mr-1", Attribution: name}); err != nil {
			t.Fatalf("%s: err = %v", name, err)
		}
		if f.mrFindReq.GetAttributionFilter() != want {
			t.Fatalf("%s: wire attribution = %v, want %v", name, f.mrFindReq.GetAttributionFilter(), want)
		}
	}
}

// A missing merge-request identity or a filter name the contract does not
// define never reaches the backend.
func TestListMergeRequestFindingsMalformedIsRefused(t *testing.T) {
	for _, q := range []MergeRequestFindingsQuery{
		{},
		{MergeRequestID: "mr-1", ScannerClass: "XRAY"},
		{MergeRequestID: "mr-1", Severity: "APOCALYPTIC"},
		{MergeRequestID: "mr-1", Attribution: "SOMETIMES"},
	} {
		f := &fakeService{}
		_, err := New(f).ListMergeRequestFindings(context.Background(), read(), q)
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("%+v: err = %v, want ErrMalformed", q, err)
		}
		if f.mrFindReq != nil {
			t.Fatalf("%+v: backend was called for a malformed query", q)
		}
	}
}

// The authorized page is shaped field for field: the finding, the triage
// state attached to its identity, the head-revision location, the
// attribution status, and the summary naming what was compared (SPEC-0028).
func TestListMergeRequestFindingsShapesPage(t *testing.T) {
	f := &fakeService{mrFindResp: &securityv1.ListMergeRequestFindingsResponse{
		Findings: []*securityv1.MergeRequestFindingView{
			{
				Finding: &securityv1.Finding{
					FindingId: "finding-a", RepositoryId: "repo-a",
					ScannerClass: securityv1.ScannerClass_SCANNER_CLASS_SAST,
					ToolName:     "scanner-a", RuleId: "rule-1",
					Severity:  securityv1.FindingSeverity_FINDING_SEVERITY_HIGH,
					Lifecycle: securityv1.FindingLifecycle_FINDING_LIFECYCLE_OPEN,
					Location:  &securityv1.FindingLocation{ArtifactPath: "app/main.go"},
				},
				Triage: &securityv1.TriageRecord{
					TriageId: "triage-1", FindingId: "finding-a", RepositoryId: "repo-a",
					State: securityv1.TriageState_TRIAGE_STATE_ACCEPT, Justification: "risk owned",
					Version: 2, ActorId: "actor-a",
				},
				HeadLocation: &securityv1.FindingLocation{
					ArtifactPath: "app/main.go", EnclosingContent: "func handle",
					Component: "app", ComponentVersion: "1.0",
				},
				Attribution: securityv1.AttributionStatus_ATTRIBUTION_STATUS_ATTRIBUTED,
			},
			{
				Finding: &securityv1.Finding{
					FindingId: "finding-b", RepositoryId: "repo-a",
					Severity: securityv1.FindingSeverity_FINDING_SEVERITY_LOW,
				},
				Attribution:       securityv1.AttributionStatus_ATTRIBUTION_STATUS_PRE_EXISTING,
				UnavailableReason: securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_UNSPECIFIED,
			},
		},
		NextPageToken: "next",
		Summary: &securityv1.AttributionSummary{
			Status:             securityv1.AttributionStatus_ATTRIBUTION_STATUS_ATTRIBUTED,
			HeadRevision:       "head-rev",
			MergeBaseRevision:  "base-rev",
			Stale:              true,
			AttributedLow:      1,
			AttributedMedium:   2,
			AttributedHigh:     3,
			AttributedCritical: 4,
		},
	}}
	page, err := New(f).ListMergeRequestFindings(context.Background(), read(),
		MergeRequestFindingsQuery{MergeRequestID: "mr-1"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if page.NextPageToken != "next" || len(page.Findings) != 2 {
		t.Fatalf("page = %+v", page)
	}
	// Order comes from the backend untouched.
	got := page.Findings[0]
	if got.Finding.FindingID != "finding-a" || got.Finding.RepositoryID != "repo-a" ||
		got.Finding.ScannerClass != "SAST" || got.Finding.Severity != "HIGH" ||
		got.Finding.Lifecycle != "OPEN" || got.Finding.ArtifactPath != "app/main.go" {
		t.Fatalf("finding = %+v", got.Finding)
	}
	if got.Triage == nil || got.Triage.TriageID != "triage-1" || got.Triage.State != TriageAccept ||
		got.Triage.Justification != "risk owned" || got.Triage.Version != 2 || got.Triage.ActorID != "actor-a" {
		t.Fatalf("triage = %+v", got.Triage)
	}
	if got.HeadArtifactPath != "app/main.go" || got.HeadEnclosingContent != "func handle" ||
		got.HeadComponent != "app" || got.HeadComponentVersion != "1.0" {
		t.Fatalf("head location = %+v", got)
	}
	if got.Attribution != "ATTRIBUTED" || got.UnavailableReason != "" {
		t.Fatalf("attribution = %+v", got)
	}
	// Absent triage is nil — the only meaning of absence here.
	if page.Findings[1].Triage != nil {
		t.Fatalf("triage = %+v", page.Findings[1].Triage)
	}
	if page.Findings[1].Attribution != "PRE_EXISTING" {
		t.Fatalf("attribution = %+v", page.Findings[1])
	}
	summary := page.Summary
	if summary.Status != "ATTRIBUTED" || summary.UnavailableReason != "" ||
		summary.HeadRevision != "head-rev" || summary.MergeBaseRevision != "base-rev" || !summary.Stale ||
		summary.AttributedLow != 1 || summary.AttributedMedium != 2 ||
		summary.AttributedHigh != 3 || summary.AttributedCritical != 4 {
		t.Fatalf("summary = %+v", summary)
	}
}

// An UNAVAILABLE comparison is shaped with its reason, never degraded toward
// an empty page (SPEC-0028 AC7).
func TestListMergeRequestFindingsShapesUnavailable(t *testing.T) {
	for wire, want := range map[securityv1.AttributionUnavailableReason]string{
		securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_BASE_NOT_SCANNED:    "BASE_NOT_SCANNED",
		securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_HEAD_SCAN_FAILED:    "HEAD_SCAN_FAILED",
		securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_HEAD_SCAN_TIMED_OUT: "HEAD_SCAN_TIMED_OUT",
		securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_HEAD_SCAN_NOT_RUN:   "HEAD_SCAN_NOT_RUN",
		securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_NO_MERGE_BASE:       "NO_MERGE_BASE",
	} {
		f := &fakeService{mrFindResp: &securityv1.ListMergeRequestFindingsResponse{
			Summary: &securityv1.AttributionSummary{
				Status:            securityv1.AttributionStatus_ATTRIBUTION_STATUS_UNAVAILABLE,
				UnavailableReason: wire,
			},
		}}
		page, err := New(f).ListMergeRequestFindings(context.Background(), read(),
			MergeRequestFindingsQuery{MergeRequestID: "mr-1"})
		if err != nil {
			t.Fatalf("%v: err = %v", wire, err)
		}
		if page.Summary.Status != "UNAVAILABLE" || page.Summary.UnavailableReason != want {
			t.Fatalf("%v: summary = %+v, want reason %s", wire, page.Summary, want)
		}
	}
}

// A backend refusal passes through untouched; the coarse shape is applied by
// the HTTP surface, never by rewriting the reason here.
func TestListMergeRequestFindingsBackendErrorPassesThrough(t *testing.T) {
	refusal := errors.New("security: unavailable")
	f := &fakeService{err: refusal}
	if _, err := New(f).ListMergeRequestFindings(context.Background(), read(),
		MergeRequestFindingsQuery{MergeRequestID: "mr-1"}); !errors.Is(err, refusal) {
		t.Fatalf("err = %v", err)
	}
}
