package security

import (
	"context"
	"errors"
	"testing"
	"time"

	securityv1 "github.com/gitfrok/bff/gen/proto/security/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeService records what crossed the wire and answers with canned responses.
type fakeService struct {
	triageReq  *securityv1.SetTriageRequest
	listReq    *securityv1.ListFindingsRequest
	summaryReq *securityv1.GetFindingsSummaryRequest
	mrFindReq  *securityv1.ListMergeRequestFindingsRequest
	triageResp *securityv1.SetTriageResponse
	listResp   *securityv1.ListFindingsResponse
	summaryRes *securityv1.GetFindingsSummaryResponse
	mrFindResp *securityv1.ListMergeRequestFindingsResponse
	err        error
}

func (f *fakeService) IngestScanResults(context.Context, *securityv1.IngestScanResultsRequest, ...grpc.CallOption) (*securityv1.IngestScanResultsResponse, error) {
	return nil, f.err
}

func (f *fakeService) GetFinding(context.Context, *securityv1.GetFindingRequest, ...grpc.CallOption) (*securityv1.GetFindingResponse, error) {
	return nil, f.err
}

func (f *fakeService) ListFindings(_ context.Context, req *securityv1.ListFindingsRequest, _ ...grpc.CallOption) (*securityv1.ListFindingsResponse, error) {
	f.listReq = req
	return f.listResp, f.err
}

func (f *fakeService) SetTriage(_ context.Context, req *securityv1.SetTriageRequest, _ ...grpc.CallOption) (*securityv1.SetTriageResponse, error) {
	f.triageReq = req
	return f.triageResp, f.err
}

func (f *fakeService) GetTriage(context.Context, *securityv1.GetTriageRequest, ...grpc.CallOption) (*securityv1.GetTriageResponse, error) {
	return nil, f.err
}

func (f *fakeService) GetFindingsSummary(_ context.Context, req *securityv1.GetFindingsSummaryRequest, _ ...grpc.CallOption) (*securityv1.GetFindingsSummaryResponse, error) {
	f.summaryReq = req
	return f.summaryRes, f.err
}

func (f *fakeService) ListMergeRequestFindings(_ context.Context, req *securityv1.ListMergeRequestFindingsRequest, _ ...grpc.CallOption) (*securityv1.ListMergeRequestFindingsResponse, error) {
	f.mrFindReq = req
	return f.mrFindResp, f.err
}

func read() aggregate.ReadContext {
	return aggregate.ReadContext{
		TenantID: "tenant-a", ActorID: "actor-a", RequestID: "request-a",
		ActorRoles: []string{"member"},
	}
}

// The wire context carries exactly the session's verified identity — tenant,
// actor, roles, request ID — and the contract gives a dashboard request no
// field to assert a repository set or a permission claim (SPEC-0026 AC6).
func TestSetTriageForwardsIdentityOnly(t *testing.T) {
	f := &fakeService{triageResp: &securityv1.SetTriageResponse{Record: &securityv1.TriageRecord{}}}
	_, err := New(f).SetTriage(context.Background(), read(), TriageRequest{
		FindingID: "finding-a", State: TriageAccept, Justification: "risk owned", ExpectedVersion: 2,
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	ctx := f.triageReq.GetContext()
	if ctx.GetTenantId() != "tenant-a" || ctx.GetActorId() != "actor-a" || ctx.GetRequestId() != "request-a" {
		t.Fatalf("context = %v", ctx)
	}
	//arch:allow-inline-authz this compares a forwarded role string for equality in a test; it grants nothing
	if len(ctx.GetActorRoles()) != 1 || ctx.GetActorRoles()[0] != "member" {
		t.Fatalf("roles = %v", ctx.GetActorRoles())
	}
	if f.triageReq.GetFindingId() != "finding-a" || f.triageReq.GetJustification() != "risk owned" ||
		f.triageReq.GetExpectedVersion() != 2 {
		t.Fatalf("request = %v", f.triageReq)
	}
	if f.triageReq.GetState() != securityv1.TriageState_TRIAGE_STATE_ACCEPT {
		t.Fatalf("state = %v", f.triageReq.GetState())
	}
}

// Every named decision maps onto its contract enum.
func TestSetTriageStates(t *testing.T) {
	for state, want := range map[TriageState]securityv1.TriageState{
		TriageAccept:        securityv1.TriageState_TRIAGE_STATE_ACCEPT,
		TriageFalsePositive: securityv1.TriageState_TRIAGE_STATE_FALSE_POSITIVE,
		TriageFix:           securityv1.TriageState_TRIAGE_STATE_FIX,
		TriageDefer:         securityv1.TriageState_TRIAGE_STATE_DEFER,
	} {
		f := &fakeService{triageResp: &securityv1.SetTriageResponse{Record: &securityv1.TriageRecord{}}}
		if _, err := New(f).SetTriage(context.Background(), read(), TriageRequest{FindingID: "finding-a", State: state}); err != nil {
			t.Fatalf("%s: err = %v", state, err)
		}
		if f.triageReq.GetState() != want {
			t.Fatalf("%s: wire state = %v, want %v", state, f.triageReq.GetState(), want)
		}
	}
}

// A decision the contract does not name never reaches the backend: clearing
// a state is not a v1 operation, so there is no default to fall back to
// (SPEC-0026 AC5).
func TestSetTriageUnknownStateIsMalformed(t *testing.T) {
	for _, name := range []string{"", "UNSPECIFIED", "EVERYTHING"} {
		f := &fakeService{}
		_, err := New(f).SetTriage(context.Background(), read(), TriageRequest{FindingID: "finding-a", State: TriageState(name)})
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("%q: err = %v, want ErrMalformed", name, err)
		}
		if f.triageReq != nil {
			t.Fatalf("%q: backend was called for an unnamed state", name)
		}
	}
}

// The record now in force is shaped field for field; the adapter adds
// nothing and drops nothing.
func TestSetTriageShapesRecord(t *testing.T) {
	when := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	f := &fakeService{triageResp: &securityv1.SetTriageResponse{Record: &securityv1.TriageRecord{
		TriageId: "triage-1", FindingId: "finding-a", TenantId: "tenant-a", RepositoryId: "repo-a",
		State: securityv1.TriageState_TRIAGE_STATE_FIX, Justification: "patch ready",
		Version: 3, ActorId: "actor-a", OccurredAt: timestamppb.New(when),
	}}}
	got, err := New(f).SetTriage(context.Background(), read(), TriageRequest{FindingID: "finding-a", State: TriageFix})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got.TriageID != "triage-1" || got.FindingID != "finding-a" || got.RepositoryID != "repo-a" ||
		got.State != TriageFix || got.Justification != "patch ready" || got.Version != 3 ||
		got.ActorID != "actor-a" || !got.OccurredAt.Equal(when) {
		t.Fatalf("triage = %+v", got)
	}
}

// The dashboard filters cross the wire with the contract's empty/zero
// semantics and the age and owning-team dimensions SPEC-0026 AC2 adds.
func TestListFindingsForwardsFilters(t *testing.T) {
	f := &fakeService{listResp: &securityv1.ListFindingsResponse{}}
	_, err := New(f).ListFindings(context.Background(), read(), Filters{
		Repository: "repo-a", ScannerClass: "SAST", Severity: "HIGH", Lifecycle: "OPEN",
		MinAgeDays: 3, MaxAgeDays: 30, OwningTeam: "team-a",
	}, 25, "tok")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	req := f.listReq
	if req.GetRepositoryFilter() != "repo-a" || req.GetScannerClassFilter() != securityv1.ScannerClass_SCANNER_CLASS_SAST ||
		req.GetSeverityFilter() != securityv1.FindingSeverity_FINDING_SEVERITY_HIGH ||
		req.GetLifecycleFilter() != securityv1.FindingLifecycle_FINDING_LIFECYCLE_OPEN {
		t.Fatalf("filters = %v", req)
	}
	if req.GetMinAgeDays() != 3 || req.GetMaxAgeDays() != 30 || req.GetOwningTeamFilter() != "team-a" {
		t.Fatalf("dashboard filters = %v", req)
	}
	if req.GetPageSize() != 25 || req.GetPageToken() != "tok" {
		t.Fatalf("paging = %v", req)
	}
	if req.GetContext().GetTenantId() != "tenant-a" || req.GetContext().GetActorId() != "actor-a" {
		t.Fatalf("context = %v", req.GetContext())
	}
}

// An empty filter set is the org-wide read: every filter field crosses the
// wire as its UNSPECIFIED/empty/zero value (SPEC-0026 AC1).
func TestListFindingsEmptyFiltersAreUnfiltered(t *testing.T) {
	f := &fakeService{listResp: &securityv1.ListFindingsResponse{}}
	if _, err := New(f).ListFindings(context.Background(), read(), Filters{}, 0, ""); err != nil {
		t.Fatalf("err = %v", err)
	}
	req := f.listReq
	if req.GetRepositoryFilter() != "" || req.GetScannerClassFilter() != securityv1.ScannerClass_SCANNER_CLASS_UNSPECIFIED ||
		req.GetSeverityFilter() != securityv1.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED ||
		req.GetLifecycleFilter() != securityv1.FindingLifecycle_FINDING_LIFECYCLE_UNSPECIFIED ||
		req.GetMinAgeDays() != 0 || req.GetMaxAgeDays() != 0 || req.GetOwningTeamFilter() != "" {
		t.Fatalf("filters = %v", req)
	}
}

// A filter name the contract does not define never reaches the backend.
func TestListFindingsUnnamedFilterIsMalformed(t *testing.T) {
	for _, filters := range []Filters{
		{ScannerClass: "XRAY"},
		{Severity: "APOCALYPTIC"},
		{Lifecycle: "SOMETIMES"},
	} {
		f := &fakeService{}
		_, err := New(f).ListFindings(context.Background(), read(), filters, 0, "")
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("%+v: err = %v, want ErrMalformed", filters, err)
		}
		if f.listReq != nil {
			t.Fatalf("%+v: backend was called for an unnamed filter", filters)
		}
	}
}

// The authorized page is shaped field for field; order and membership come
// from the backend untouched, and the adapter adds nothing.
func TestListFindingsShapesPage(t *testing.T) {
	f := &fakeService{listResp: &securityv1.ListFindingsResponse{
		Findings: []*securityv1.Finding{{
			FindingId: "finding-a", RepositoryId: "repo-a",
			ScannerClass: securityv1.ScannerClass_SCANNER_CLASS_DEPENDENCY,
			ToolName:     "scanner-b", ToolVersion: "1.2", RuleId: "CVE-2026-0001",
			Severity: securityv1.FindingSeverity_FINDING_SEVERITY_CRITICAL,
			Location: &securityv1.FindingLocation{
				ArtifactPath: "go.mod", Component: "example/lib", ComponentVersion: "0.9.0",
			},
			Lifecycle:       securityv1.FindingLifecycle_FINDING_LIFECYCLE_OPEN,
			FirstSeenScanId: "scan-1", LastSeenScanId: "scan-2",
			Provenance: []byte(`{"native":true}`), ProvenanceMediaType: "application/json",
		}},
		NextPageToken: "next",
	}}
	page, err := New(f).ListFindings(context.Background(), read(), Filters{}, 0, "")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if page.NextPageToken != "next" || len(page.Findings) != 1 {
		t.Fatalf("page = %+v", page)
	}
	got := page.Findings[0]
	if got.FindingID != "finding-a" || got.RepositoryID != "repo-a" || got.ScannerClass != "DEPENDENCY" ||
		got.ToolName != "scanner-b" || got.ToolVersion != "1.2" || got.RuleID != "CVE-2026-0001" ||
		got.Severity != "CRITICAL" || got.Lifecycle != "OPEN" || got.ArtifactPath != "go.mod" ||
		got.Component != "example/lib" || got.ComponentVersion != "0.9.0" ||
		got.FirstSeenScanID != "scan-1" || got.LastSeenScanID != "scan-2" ||
		string(got.Provenance) != `{"native":true}` || got.ProvenanceMediaType != "application/json" {
		t.Fatalf("finding = %+v", got)
	}
}

// Summary forwards the filters and the requested facet dimensions untouched
// and shapes the authorized counts field for field: which values appear is
// the backend's decision, and an unauthorized value is absent, not zero
// (SPEC-0027 AC4).
func TestFindingsSummaryForwardsAndShapes(t *testing.T) {
	f := &fakeService{summaryRes: &securityv1.GetFindingsSummaryResponse{
		TotalCount: 7,
		Facets: []*securityv1.SummaryFacet{{
			Dimension: "severity",
			Values: []*securityv1.SummaryFacetValue{
				{Value: "HIGH", Count: 4}, {Value: "CRITICAL", Count: 3},
			},
		}},
	}}
	summary, err := New(f).FindingsSummary(context.Background(), read(),
		Filters{Repository: "repo-a", OwningTeam: "team-a"}, []string{"severity", "owning_team"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	req := f.summaryReq
	if req.GetRepositoryFilter() != "repo-a" || req.GetOwningTeamFilter() != "team-a" {
		t.Fatalf("filters = %v", req)
	}
	if len(req.GetFacetDimensions()) != 2 || req.GetFacetDimensions()[0] != "severity" || req.GetFacetDimensions()[1] != "owning_team" {
		t.Fatalf("dimensions = %v", req.GetFacetDimensions())
	}
	if summary.TotalCount != 7 || len(summary.Facets) != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	facet := summary.Facets[0]
	if facet.Dimension != "severity" || len(facet.Values) != 2 ||
		facet.Values[0].Value != "HIGH" || facet.Values[0].Count != 4 ||
		facet.Values[1].Value != "CRITICAL" || facet.Values[1].Count != 3 {
		t.Fatalf("facet = %+v", facet)
	}
}

// A backend refusal passes through untouched; the coarse shape is applied by
// the HTTP surface, never by rewriting the reason here.
func TestBackendErrorPassesThrough(t *testing.T) {
	refusal := errors.New("security: unavailable")
	client := New(&fakeService{err: refusal})
	if _, err := client.ListFindings(context.Background(), read(), Filters{}, 0, ""); !errors.Is(err, refusal) {
		t.Fatalf("list err = %v", err)
	}
	if _, err := client.FindingsSummary(context.Background(), read(), Filters{}, nil); !errors.Is(err, refusal) {
		t.Fatalf("summary err = %v", err)
	}
	if _, err := client.SetTriage(context.Background(), read(), TriageRequest{FindingID: "finding-a", State: TriageFix}); !errors.Is(err, refusal) {
		t.Fatalf("triage err = %v", err)
	}
}
