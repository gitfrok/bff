// Package mr serves the minimal merge-request HTTP surface the Phase-1 web
// bar needs (SPEC-0009, plan risk note: "minimal MR page is sufficient").
//
// It shapes and forwards, exactly like the browser package: identity comes
// only from the authenticated session, the backend owns every decision, and
// no request can assert a tenant, an actor, a role, an approval count, or an
// authorization outcome. An MR view is a repository read; open/review/merge
// are writes that travel with the session's verified context.
package mr

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/codereview"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Session resolves the verified identity a request runs under, as in the
// browser package.
type Session interface {
	ReadContext(*http.Request) (aggregate.ReadContext, bool)
}

// MergeRequests is the narrow MR port this surface shapes. The backend owns
// every decision; this interface carries only the verified context and the
// request's own fields.
type MergeRequests interface {
	Get(context.Context, aggregate.ReadContext, string) (*codereview.MergeRequest, error)
	Create(context.Context, aggregate.ReadContext, string, string, string, string, bool) (*codereview.MergeRequest, error)
	SubmitReview(context.Context, aggregate.ReadContext, string, string, string, string, int64) (*codereview.MergeRequest, error)
	Merge(context.Context, aggregate.ReadContext, string, int64) (*codereview.MergeRequest, error)
	// MarkReady moves a DRAFT merge request to OPEN (ADR-0087, SPEC-0064).
	MarkReady(context.Context, aggregate.ReadContext, string, int64) (*codereview.MergeRequest, error)
	// LinkExternalIssue and UnlinkExternalIssue reference an issue in the customer's
	// own tracker (SPEC-0059). They are on this port because a reference is a
	// property of a merge request — there is no issue surface for them to belong to,
	// which is ADR-0074's accepted scope.
	LinkExternalIssue(context.Context, aggregate.ReadContext, string, string, string, string) (*codereview.MergeRequest, error)
	UnlinkExternalIssue(context.Context, aggregate.ReadContext, string, string, string) (*codereview.MergeRequest, error)
}

// Handler serves the minimal MR surface.
type Handler struct {
	client  MergeRequests
	imports ImportedHistory
	session Session
}

// New wires the handler onto the codereview client. A nil imports port means
// this deployment serves no imported history, and the route refuses rather than
// returning an empty page a reader could mistake for "this import has none".
func New(client MergeRequests, imports ImportedHistory, session Session) *Handler {
	return &Handler{client: client, imports: imports, session: session}
}

// MRView is the JSON shape the web page consumes. It carries only review
// state; no policy outcome, approval count, or authorization result.
type MRView struct {
	MergeRequestID string    `json:"merge_request_id"`
	RepositoryID   string    `json:"repository_id"`
	SourceRef      string    `json:"source_ref"`
	TargetRef      string    `json:"target_ref"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	CreatorID      string    `json:"creator_id"`
	State          string    `json:"state"`
	HeadRevision   string    `json:"head_revision"`
	Version        int64     `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	// ExternalIssues are pointers to issues in the customer's tracker (SPEC-0059).
	// There is no title, status or assignee field here, and a test asserts the body
	// carries none: this product references issues, it does not store them.
	ExternalIssues []ExternalIssueView `json:"external_issues"`
}

// ExternalIssueView is one reference as the browser reads it.
type ExternalIssueView struct {
	Tracker  string `json:"tracker"`
	IssueKey string `json:"issue_key"`
	URL      string `json:"url"`
	LinkedBy string `json:"linked_by"`
	LinkedAt string `json:"linked_at"`
}

// Routes returns the MR surface.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/repositories/{repository_id}/merge_requests/{merge_request_id}", h.get)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/merge_requests", h.create)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/review", h.review)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/ready", h.ready)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/merge", h.merge)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/external_issues", h.linkExternalIssue)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/external_issues/unlink", h.unlinkExternalIssue)
	mux.HandleFunc("GET /v1/repositories/{repository_id}/imports/{import_id}/history", h.importedHistory)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux alongside
// other /v1/repositories/ handlers; the mux routes each request to the right
// method on this handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		denied(w)
		return
	}
	read.RepositoryID = r.PathValue("repository_id")
	if !validHandle(read.RepositoryID) {
		denied(w)
		return
	}
	mr, err := h.client.Get(r.Context(), read, r.PathValue("merge_request_id"))
	if err != nil {
		denied(w)
		return
	}
	writeJSON(w, viewOf(mr))
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		denied(w)
		return
	}
	read.RepositoryID = r.PathValue("repository_id")
	if err := r.ParseForm(); err != nil {
		denied(w)
		return
	}
	read.RequestID = newRequestID()
	mr, err := h.client.Create(r.Context(), read,
		r.PostFormValue("source_ref"), r.PostFormValue("target_ref"),
		r.PostFormValue("title"), r.PostFormValue("description"),
		r.PostFormValue("draft") == "on" || r.PostFormValue("draft") == "true")
	if err != nil {
		denied(w)
		return
	}
	writeJSON(w, viewOf(mr))
}

func (h *Handler) review(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		denied(w)
		return
	}
	read.RepositoryID = r.PathValue("repository_id")
	if err := r.ParseForm(); err != nil {
		denied(w)
		return
	}
	read.RequestID = newRequestID()
	version, err := strconv.ParseInt(r.PostFormValue("expected_version"), 10, 64)
	if err != nil {
		denied(w)
		return
	}
	mr, err := h.client.SubmitReview(r.Context(), read,
		r.PathValue("merge_request_id"), r.PostFormValue("disposition"),
		r.PostFormValue("comment"), r.PostFormValue("head_revision"), version)
	if err != nil {
		denied(w)
		return
	}
	writeJSON(w, viewOf(mr))
}

// ready marks a draft ready for review (ADR-0087, SPEC-0064). Same shape as
// merge: the expected version travels with the form; the state machine is the
// backend's decision.
func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		denied(w)
		return
	}
	read.RepositoryID = r.PathValue("repository_id")
	if err := r.ParseForm(); err != nil {
		denied(w)
		return
	}
	read.RequestID = newRequestID()
	version, err := strconv.ParseInt(r.PostFormValue("expected_version"), 10, 64)
	if err != nil {
		denied(w)
		return
	}
	mr, err := h.client.MarkReady(r.Context(), read, r.PathValue("merge_request_id"), version)
	if err != nil {
		denied(w)
		return
	}
	writeJSON(w, viewOf(mr))
}

func (h *Handler) merge(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		denied(w)
		return
	}
	read.RepositoryID = r.PathValue("repository_id")
	if err := r.ParseForm(); err != nil {
		denied(w)
		return
	}
	read.RequestID = newRequestID()
	version, err := strconv.ParseInt(r.PostFormValue("expected_version"), 10, 64)
	if err != nil {
		denied(w)
		return
	}
	mr, err := h.client.Merge(r.Context(), read, r.PathValue("merge_request_id"), version)
	if err != nil {
		denied(w)
		return
	}
	writeJSON(w, viewOf(mr))
}

// linkExternalIssue references an issue that lives elsewhere. A form, as every other
// write on this frontend's behalf is.
func (h *Handler) linkExternalIssue(w http.ResponseWriter, r *http.Request) {
	read, ok := h.beginWrite(w, r)
	if !ok {
		return
	}
	mr, err := h.client.LinkExternalIssue(r.Context(), read,
		r.PathValue("merge_request_id"),
		r.PostFormValue("tracker"), r.PostFormValue("issue_key"), r.PostFormValue("url"))
	if err != nil {
		referenceRefusal(w, err)
		return
	}
	writeJSON(w, viewOf(mr))
}

// unlinkExternalIssue removes a reference by tracker and key. A separate route rather
// than a DELETE, because this is a plain HTML form and a form cannot issue one.
func (h *Handler) unlinkExternalIssue(w http.ResponseWriter, r *http.Request) {
	read, ok := h.beginWrite(w, r)
	if !ok {
		return
	}
	mr, err := h.client.UnlinkExternalIssue(r.Context(), read,
		r.PathValue("merge_request_id"), r.PostFormValue("tracker"), r.PostFormValue("issue_key"))
	if err != nil {
		referenceRefusal(w, err)
		return
	}
	writeJSON(w, viewOf(mr))
}

// beginWrite resolves the session and parses the form for a write on this surface.
func (h *Handler) beginWrite(w http.ResponseWriter, r *http.Request) (aggregate.ReadContext, bool) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		denied(w)
		return aggregate.ReadContext{}, false
	}
	read.RepositoryID = r.PathValue("repository_id")
	if !validHandle(read.RepositoryID) {
		denied(w)
		return aggregate.ReadContext{}, false
	}
	if err := r.ParseForm(); err != nil {
		denied(w)
		return aggregate.ReadContext{}, false
	}
	read.RequestID = newRequestID()
	return read, true
}

// referenceRefusal keeps the two outcomes the backend distinguishes and collapses
// everything else.
//
// A malformed reference and a full list are both facts about what the caller just
// sent or is already looking at, so naming them discloses nothing. Whether the merge
// request exists stays the coarse refusal.
func referenceRefusal(w http.ResponseWriter, err error) {
	switch status.Code(err) {
	case codes.InvalidArgument:
		w.Header().Set("Cache-Control", "private, no-store")
		http.Error(w, "a reference needs a tracker, an issue key and an https URL", http.StatusBadRequest)
	case codes.ResourceExhausted:
		w.Header().Set("Cache-Control", "private, no-store")
		http.Error(w, "this merge request has as many issue references as it can carry", http.StatusConflict)
	default:
		denied(w)
	}
}

func viewOf(mr *codereview.MergeRequest) MRView {
	return MRView{
		MergeRequestID: mr.MergeRequestID, RepositoryID: mr.RepositoryID,
		SourceRef: mr.SourceRef, TargetRef: mr.TargetRef,
		Title: mr.Title, Description: mr.Description,
		CreatorID: mr.CreatorID, State: mr.State,
		HeadRevision: mr.HeadRevision, Version: mr.Version, CreatedAt: mr.CreatedAt,
		ExternalIssues: externalIssueViews(mr.ExternalIssues),
	}
}

// externalIssueViews shapes the references for the browser.
func externalIssueViews(references []codereview.ExternalIssue) []ExternalIssueView {
	out := make([]ExternalIssueView, 0, len(references))
	for _, reference := range references {
		out = append(out, ExternalIssueView{
			Tracker: reference.Tracker, IssueKey: reference.IssueKey, URL: reference.URL,
			LinkedBy: reference.LinkedBy, LinkedAt: reference.LinkedAt,
		})
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// denied is the one refusal this surface returns: it distinguishes nothing
// about what exists, what is allowed, or why.
func denied(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "merge request unavailable", http.StatusNotFound)
}

func validHandle(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case (r == '-' || r == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

func newRequestID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}
