package mr

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/codereview"
)

// maxPageSize bounds one page of imported history. An import may hold tens of
// thousands of records (SPEC-0011 volume assumption), and a caller-chosen page
// size is a caller-chosen amount of work for the backend.
const maxPageSize = 200

// ImportedHistory is the narrow read port for an import's history. Reading it
// is a repository read like any other: the tenant, the actor and its roles come
// only from the session.
type ImportedHistory interface {
	ListImportedHistory(ctx context.Context, read aggregate.ReadContext, importID string, pageSize int32, pageToken string) (codereview.ImportedHistoryPage, error)
}

// ProvenanceView is the provenance block as the web page consumes it.
//
// Class is always present and never empty: a page that has to guess whether a
// record is imported will eventually guess "first-party", and an imported
// approval rendered as a platform approval is exactly what ADR-0029 forbids
// (SPEC-0011 AC23).
type ProvenanceView struct {
	Class          string     `json:"class"`
	ImportID       string     `json:"import_id"`
	SourceSystem   string     `json:"source_system"`
	SourceInstance string     `json:"source_instance"`
	SourceRef      string     `json:"source_ref"`
	DeclaredActor  string     `json:"declared_actor"`
	DeclaredAt     *time.Time `json:"declared_at"`
	PayloadDigest  string     `json:"payload_digest"`
}

// ImportedCommentView is one imported comment.
type ImportedCommentView struct {
	CommentID string `json:"comment_id"`
	// The source's own handle for the author. It is deliberately not named
	// author_id: an unmapped foreign handle never resolves to a platform user
	// (SPEC-0011 AC14).
	DeclaredActor string         `json:"declared_actor"`
	Body          string         `json:"body"`
	DeclaredAt    *time.Time     `json:"declared_at"`
	Provenance    ProvenanceView `json:"provenance"`
}

// ImportedThreadView is one imported thread.
type ImportedThreadView struct {
	ThreadID       string `json:"thread_id"`
	MergeRequestID string `json:"merge_request_id"`
	Path           string `json:"path"`
	Anchor         string `json:"anchor"`
	// Approximate is true when the thread no longer anchors to a diff position —
	// the source force-pushed, or the commits are gone. The API says so rather
	// than leaving the page to infer it from the anchor enum, so a degraded
	// anchor cannot be rendered as an exact one (SPEC-0011 AC5).
	Approximate bool                  `json:"approximate"`
	Comments    []ImportedCommentView `json:"comments"`
	Provenance  ProvenanceView        `json:"provenance"`
}

// ImportedApprovalView is one imported approval.
type ImportedApprovalView struct {
	ApprovalID     string         `json:"approval_id"`
	MergeRequestID string         `json:"merge_request_id"`
	DeclaredActor  string         `json:"declared_actor"`
	DeclaredAt     *time.Time     `json:"declared_at"`
	Provenance     ProvenanceView `json:"provenance"`
	// SatisfiesPolicy is always false here. It is stated rather than omitted so
	// the page renders the fact from the API instead of from a convention it
	// could forget: an imported approval never satisfies a merge policy
	// (SPEC-0011 AC13, ADR-0029 §4).
	SatisfiesPolicy bool `json:"satisfies_policy"`
}

// ImportedMRView is one imported merge request as the source declared it.
type ImportedMRView struct {
	MergeRequestID  string                 `json:"merge_request_id"`
	SourceRef       string                 `json:"source_ref"`
	TargetRef       string                 `json:"target_ref"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	State           string                 `json:"state"`
	DeclaredCreator string                 `json:"declared_creator"`
	Threads         []ImportedThreadView   `json:"threads"`
	Approvals       []ImportedApprovalView `json:"approvals"`
	Provenance      ProvenanceView         `json:"provenance"`
}

// ImportedHistoryView is one page of imported history.
type ImportedHistoryView struct {
	MergeRequests []ImportedMRView `json:"merge_requests"`
	NextPageToken string           `json:"next_page_token"`
}

func (h *Handler) importedHistory(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		denied(w)
		return
	}
	if h.imports == nil {
		denied(w)
		return
	}
	read.RepositoryID = r.PathValue("repository_id")
	importID := r.PathValue("import_id")
	if !validHandle(read.RepositoryID) || !validHandle(importID) {
		denied(w)
		return
	}
	pageSize, ok := pageSizeOf(r.URL.Query().Get("page_size"))
	if !ok {
		denied(w)
		return
	}
	page, err := h.imports.ListImportedHistory(r.Context(), read, importID, pageSize, r.URL.Query().Get("page_token"))
	if err != nil {
		denied(w)
		return
	}
	writeJSON(w, importedViewOf(page))
}

// pageSizeOf reads the requested page size. Absent means the server's default;
// anything unparseable, negative or over the cap is refused rather than
// silently clamped, so a caller is never told it got a page it did not ask for.
func pageSizeOf(raw string) (int32, bool) {
	if raw == "" {
		return 0, true
	}
	size, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || size < 0 || size > maxPageSize {
		return 0, false
	}
	return int32(size), true
}

func importedViewOf(page codereview.ImportedHistoryPage) ImportedHistoryView {
	view := ImportedHistoryView{
		MergeRequests: make([]ImportedMRView, 0, len(page.MergeRequests)),
		NextPageToken: page.NextPageToken,
	}
	for _, record := range page.MergeRequests {
		mr := ImportedMRView{
			MergeRequestID:  record.MergeRequestID,
			SourceRef:       record.SourceRef,
			TargetRef:       record.TargetRef,
			Title:           record.Title,
			Description:     record.Description,
			State:           record.State,
			DeclaredCreator: record.DeclaredCreator,
			Threads:         make([]ImportedThreadView, 0, len(record.Threads)),
			Approvals:       make([]ImportedApprovalView, 0, len(record.Approvals)),
			Provenance:      provenanceViewOf(record.Provenance),
		}
		for _, thread := range record.Threads {
			shaped := ImportedThreadView{
				ThreadID:       thread.ThreadID,
				MergeRequestID: thread.MergeRequestID,
				Path:           thread.Path,
				Anchor:         thread.Anchor,
				Approximate:    thread.Anchor != codereview.AnchorDiff,
				Comments:       make([]ImportedCommentView, 0, len(thread.Comments)),
				Provenance:     provenanceViewOf(thread.Provenance),
			}
			for _, comment := range thread.Comments {
				shaped.Comments = append(shaped.Comments, ImportedCommentView{
					CommentID:     comment.CommentID,
					DeclaredActor: comment.DeclaredActor,
					Body:          comment.Body,
					DeclaredAt:    declaredAt(comment.DeclaredAt),
					Provenance:    provenanceViewOf(comment.Provenance),
				})
			}
			mr.Threads = append(mr.Threads, shaped)
		}
		for _, approval := range record.Approvals {
			mr.Approvals = append(mr.Approvals, ImportedApprovalView{
				ApprovalID:     approval.ApprovalID,
				MergeRequestID: approval.MergeRequestID,
				DeclaredActor:  approval.DeclaredActor,
				DeclaredAt:     declaredAt(approval.DeclaredAt),
				Provenance:     provenanceViewOf(approval.Provenance),
				// Never computed, never configurable.
				SatisfiesPolicy: false,
			})
		}
		view.MergeRequests = append(view.MergeRequests, mr)
	}
	return view
}

func provenanceViewOf(provenance codereview.Provenance) ProvenanceView {
	class := provenance.Class
	if class == "" {
		class = codereview.ClassUnspecified
	}
	return ProvenanceView{
		Class:          class,
		ImportID:       provenance.ImportID,
		SourceSystem:   provenance.SourceSystem,
		SourceInstance: provenance.SourceInstance,
		SourceRef:      provenance.SourceRef,
		DeclaredActor:  provenance.DeclaredActor,
		DeclaredAt:     declaredAt(provenance.DeclaredAt),
		PayloadDigest:  provenance.PayloadDigest,
	}
}

// declaredAt renders an absent source-declared time as JSON null rather than as
// the zero time, which a browser would read as the year 1.
func declaredAt(at time.Time) *time.Time {
	if at.IsZero() {
		return nil
	}
	return &at
}
