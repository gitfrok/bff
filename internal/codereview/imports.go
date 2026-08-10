package codereview

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	codereviewv1 "github.com/gitfrok/bff/gen/proto/codereview/v1"
	contractsv1 "github.com/gitfrok/bff/gen/proto/contracts/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

// Provenance class names as this surface spells them. They are the contract's
// own enum names minus the CLASS_ prefix, so a reader never has to guess.
const (
	ClassUnspecified = "UNSPECIFIED"
	ClassFirstParty  = "FIRST_PARTY"
	ClassImported    = "ATTESTED_IMPORT"
)

// Anchor precisions of an imported thread. A thread whose diff position no
// longer resolves degrades to FILE, and to MERGE when the file is gone too
// (SPEC-0011 AC5).
const (
	AnchorUnspecified = "UNSPECIFIED"
	AnchorDiff        = "DIFF"
	AnchorFile        = "FILE"
	AnchorMerge       = "MERGE"
)

// ImportClient talks to the backend's ImportService. It is a separate client
// from the MergeRequestService one on purpose: imported history is a different
// service in the contracts, and mixing the two here would invite a caller to
// treat an imported record as review state this platform witnessed.
type ImportClient struct {
	service codereviewv1.ImportServiceClient
}

// NewImportClient wires the adapter onto the generated client.
func NewImportClient(service codereviewv1.ImportServiceClient) *ImportClient {
	return &ImportClient{service: service}
}

// Provenance is the shaped provenance block. Class is always populated — an
// empty string would let a renderer fall through to whatever its default
// branch draws, and ADR-0029 §1 forbids an implicit provenance default.
type Provenance struct {
	Class          string
	ImportID       string
	SourceSystem   string
	SourceInstance string
	SourceRef      string
	DeclaredActor  string
	DeclaredAt     time.Time
	PayloadDigest  string
}

// ImportedComment is one imported comment. DeclaredActor is an opaque foreign
// handle; it is never resolved to a platform user (SPEC-0011 AC14).
type ImportedComment struct {
	CommentID     string
	DeclaredActor string
	Body          string
	DeclaredAt    time.Time
	Provenance    Provenance
}

// ImportedThread is one imported thread and its comments.
type ImportedThread struct {
	ThreadID       string
	MergeRequestID string
	Path           string
	Anchor         string
	Comments       []ImportedComment
	Provenance     Provenance
}

// ImportedApproval is one imported approval. It can never satisfy a merge
// policy; the backend feeds valid_approvals from first-party reviews only
// (SPEC-0011 AC13).
type ImportedApproval struct {
	ApprovalID     string
	MergeRequestID string
	DeclaredActor  string
	DeclaredAt     time.Time
	Provenance     Provenance
}

// ImportedMergeRequest is one imported merge request as the source declared it.
type ImportedMergeRequest struct {
	MergeRequestID  string
	SourceRef       string
	TargetRef       string
	Title           string
	Description     string
	State           string
	DeclaredCreator string
	Threads         []ImportedThread
	Approvals       []ImportedApproval
	Provenance      Provenance
}

// ImportedHistoryPage is one page of an import's history.
type ImportedHistoryPage struct {
	MergeRequests []ImportedMergeRequest
	NextPageToken string
}

// ListImportedHistory returns one page of an import's imported merge requests.
func (c *ImportClient) ListImportedHistory(ctx context.Context, read aggregate.ReadContext, importID string, pageSize int32, pageToken string) (ImportedHistoryPage, error) {
	response, err := c.service.ListImportedHistory(ctx, &codereviewv1.ListImportedHistoryRequest{
		Context: &codereviewv1.ReviewCommandContext{
			TenantId:     read.TenantID,
			RepositoryId: read.RepositoryID,
			ActorId:      read.ActorID,
			ActorRoles:   read.ActorRoles,
			RequestId:    read.RequestID,
		},
		ImportId:  importID,
		PageSize:  pageSize,
		PageToken: pageToken,
	})
	if err != nil {
		return ImportedHistoryPage{}, err
	}
	page := ImportedHistoryPage{NextPageToken: response.GetNextPageToken()}
	for _, record := range response.GetMergeRequests() {
		page.MergeRequests = append(page.MergeRequests, shapeImportedMR(record))
	}
	return page, nil
}

func shapeImportedMR(record *codereviewv1.ImportedMergeRequest) ImportedMergeRequest {
	out := ImportedMergeRequest{
		MergeRequestID:  record.GetMergeRequestId(),
		SourceRef:       record.GetSourceRef(),
		TargetRef:       record.GetTargetRef(),
		Title:           record.GetTitle(),
		Description:     record.GetDescription(),
		State:           record.GetState(),
		DeclaredCreator: record.GetDeclaredCreator(),
		Provenance:      shapeProvenance(record.GetProvenance()),
	}
	for _, thread := range record.GetThreads() {
		shaped := ImportedThread{
			ThreadID:       thread.GetThreadId(),
			MergeRequestID: thread.GetMergeRequestId(),
			Path:           thread.GetPath(),
			Anchor:         shapeAnchor(thread.GetAnchor()),
			Provenance:     shapeProvenance(thread.GetProvenance()),
		}
		for _, comment := range thread.GetComments() {
			shaped.Comments = append(shaped.Comments, ImportedComment{
				CommentID:     comment.GetCommentId(),
				DeclaredActor: comment.GetDeclaredActor(),
				Body:          comment.GetBody(),
				DeclaredAt:    declaredTime(comment.GetDeclaredAt()),
				Provenance:    shapeProvenance(comment.GetProvenance()),
			})
		}
		out.Threads = append(out.Threads, shaped)
	}
	for _, approval := range record.GetApprovals() {
		out.Approvals = append(out.Approvals, ImportedApproval{
			ApprovalID:     approval.GetApprovalId(),
			MergeRequestID: approval.GetMergeRequestId(),
			DeclaredActor:  approval.GetDeclaredActor(),
			DeclaredAt:     declaredTime(approval.GetDeclaredAt()),
			Provenance:     shapeProvenance(approval.GetProvenance()),
		})
	}
	return out
}

// shapeAnchor names the anchor precision. An anchor this build cannot name
// travels as UNSPECIFIED rather than DIFF: DIFF asserts the diff position still
// resolves, and defaulting to it would turn an approximate anchor into an exact
// claim (SPEC-0011 AC5).
func shapeAnchor(anchor codereviewv1.ImportedThread_Anchor) string {
	switch anchor {
	case codereviewv1.ImportedThread_ANCHOR_DIFF:
		return AnchorDiff
	case codereviewv1.ImportedThread_ANCHOR_FILE:
		return AnchorFile
	case codereviewv1.ImportedThread_ANCHOR_MERGE:
		return AnchorMerge
	default:
		return AnchorUnspecified
	}
}

// shapeProvenance names the provenance class. A class this build cannot name
// travels as UNSPECIFIED, never as FIRST_PARTY: a record whose class the BFF
// cannot read must not reach the browser looking like one this platform
// witnessed (ADR-0029 §1).
func shapeProvenance(provenance *contractsv1.Provenance) Provenance {
	class := ClassUnspecified
	switch provenance.GetClass() {
	case contractsv1.Provenance_CLASS_FIRST_PARTY:
		class = ClassFirstParty
	case contractsv1.Provenance_CLASS_ATTESTED_IMPORT:
		class = ClassImported
	}
	return Provenance{
		Class:          class,
		ImportID:       provenance.GetImportId(),
		SourceSystem:   provenance.GetSourceSystem(),
		SourceInstance: provenance.GetSourceInstance(),
		SourceRef:      provenance.GetSourceRef(),
		DeclaredActor:  provenance.GetDeclaredActor(),
		DeclaredAt:     declaredTime(provenance.GetDeclaredAt()),
		PayloadDigest:  provenance.GetPayloadDigest(),
	}
}

// declaredTime carries a source-declared time. An absent timestamp stays the
// zero time rather than becoming the Unix epoch, so the surface never hands the
// browser a date the source never declared.
func declaredTime(at *timestamppb.Timestamp) time.Time {
	if at == nil {
		return time.Time{}
	}
	return at.AsTime()
}
