package codereview

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	codereviewv1 "github.com/gitfrok/bff/gen/proto/codereview/v1"
	contractsv1 "github.com/gitfrok/bff/gen/proto/contracts/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

// stubImportService is the backend's ImportService as far as this adapter is
// concerned. Only the read RPC is exercised; the writes are not this surface's.
type stubImportService struct {
	codereviewv1.ImportServiceClient
	response *codereviewv1.ListImportedHistoryResponse
	request  *codereviewv1.ListImportedHistoryRequest
}

func (s *stubImportService) ListImportedHistory(_ context.Context, in *codereviewv1.ListImportedHistoryRequest, _ ...grpc.CallOption) (*codereviewv1.ListImportedHistoryResponse, error) {
	s.request = in
	return s.response, nil
}

func read() aggregate.ReadContext {
	return aggregate.ReadContext{
		TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a",
		ActorRoles: []string{"developer"}, RequestID: "request-a",
	}
}

// A provenance class this build cannot name never shapes into FIRST_PARTY: a
// record the BFF cannot classify must not reach the browser looking like one
// the platform witnessed (ADR-0029 §1).
func TestUnknownProvenanceClassIsNeverFirstParty(t *testing.T) {
	service := &stubImportService{response: &codereviewv1.ListImportedHistoryResponse{
		MergeRequests: []*codereviewv1.ImportedMergeRequest{{
			MergeRequestId: "imported-1",
			Provenance:     &contractsv1.Provenance{Class: contractsv1.Provenance_CLASS_UNSPECIFIED},
		}},
	}}
	page, err := NewImportClient(service).ListImportedHistory(context.Background(), read(), "import-1", 0, "")
	if err != nil {
		t.Fatalf("list = %v", err)
	}
	if got := page.MergeRequests[0].Provenance.Class; got != ClassUnspecified {
		t.Fatalf("class = %q, want %q", got, ClassUnspecified)
	}
}

// A record with no provenance block at all is still classified — as
// UNSPECIFIED, never as an empty string a renderer would fall through on.
func TestMissingProvenanceBlockIsUnspecified(t *testing.T) {
	service := &stubImportService{response: &codereviewv1.ListImportedHistoryResponse{
		MergeRequests: []*codereviewv1.ImportedMergeRequest{{MergeRequestId: "imported-1"}},
	}}
	page, err := NewImportClient(service).ListImportedHistory(context.Background(), read(), "import-1", 0, "")
	if err != nil {
		t.Fatalf("list = %v", err)
	}
	if got := page.MergeRequests[0].Provenance.Class; got != ClassUnspecified {
		t.Fatalf("class = %q, want %q", got, ClassUnspecified)
	}
}

// An anchor this build cannot name shapes to UNSPECIFIED, not DIFF: DIFF is the
// claim that the diff position still resolves (SPEC-0011 AC5).
func TestUnknownAnchorIsNeverDiff(t *testing.T) {
	service := &stubImportService{response: &codereviewv1.ListImportedHistoryResponse{
		MergeRequests: []*codereviewv1.ImportedMergeRequest{{
			MergeRequestId: "imported-1",
			Threads: []*codereviewv1.ImportedThread{{
				ThreadId: "thread-1",
				Anchor:   codereviewv1.ImportedThread_ANCHOR_UNSPECIFIED,
			}},
		}},
	}}
	page, err := NewImportClient(service).ListImportedHistory(context.Background(), read(), "import-1", 0, "")
	if err != nil {
		t.Fatalf("list = %v", err)
	}
	if got := page.MergeRequests[0].Threads[0].Anchor; got != AnchorUnspecified {
		t.Fatalf("anchor = %q, want %q", got, AnchorUnspecified)
	}
}

// The verified identity travels to the backend; nothing else is asserted.
func TestRequestCarriesTheVerifiedContext(t *testing.T) {
	service := &stubImportService{response: &codereviewv1.ListImportedHistoryResponse{}}
	if _, err := NewImportClient(service).ListImportedHistory(context.Background(), read(), "import-1", 25, "page-1"); err != nil {
		t.Fatalf("list = %v", err)
	}
	verified := service.request.GetContext()
	if verified.GetTenantId() != "tenant-a" || verified.GetActorId() != "actor-a" || verified.GetRepositoryId() != "repo-a" {
		t.Fatalf("context = %+v", verified)
	}
	if service.request.GetImportId() != "import-1" || service.request.GetPageSize() != 25 || service.request.GetPageToken() != "page-1" {
		t.Fatalf("request = %+v", service.request)
	}
}

// An absent source-declared timestamp stays the zero time rather than becoming
// the Unix epoch.
func TestAbsentDeclaredAtStaysZero(t *testing.T) {
	service := &stubImportService{response: &codereviewv1.ListImportedHistoryResponse{
		MergeRequests: []*codereviewv1.ImportedMergeRequest{{
			MergeRequestId: "imported-1",
			Approvals: []*codereviewv1.ImportedApproval{{
				ApprovalId: "approval-1",
				Provenance: &contractsv1.Provenance{Class: contractsv1.Provenance_CLASS_ATTESTED_IMPORT},
			}},
		}},
	}}
	page, err := NewImportClient(service).ListImportedHistory(context.Background(), read(), "import-1", 0, "")
	if err != nil {
		t.Fatalf("list = %v", err)
	}
	if !page.MergeRequests[0].Approvals[0].DeclaredAt.IsZero() {
		t.Fatal("an absent declared_at became a time")
	}
}
