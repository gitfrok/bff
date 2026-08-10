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
	Create(context.Context, aggregate.ReadContext, string, string, string, string) (*codereview.MergeRequest, error)
	SubmitReview(context.Context, aggregate.ReadContext, string, string, string, string, int64) (*codereview.MergeRequest, error)
	Merge(context.Context, aggregate.ReadContext, string, int64) (*codereview.MergeRequest, error)
}

// Handler serves the minimal MR surface.
type Handler struct {
	client  MergeRequests
	session Session
}

// New wires the handler onto the codereview client.
func New(client MergeRequests, session Session) *Handler {
	return &Handler{client: client, session: session}
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
}

// Routes returns the MR surface.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/repositories/{repository_id}/merge_requests/{merge_request_id}", h.get)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/merge_requests", h.create)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/review", h.review)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/merge", h.merge)
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
		r.PostFormValue("title"), r.PostFormValue("description"))
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

func viewOf(mr *codereview.MergeRequest) MRView {
	return MRView{
		MergeRequestID: mr.MergeRequestID, RepositoryID: mr.RepositoryID,
		SourceRef: mr.SourceRef, TargetRef: mr.TargetRef,
		Title: mr.Title, Description: mr.Description,
		CreatorID: mr.CreatorID, State: mr.State,
		HeadRevision: mr.HeadRevision, Version: mr.Version, CreatedAt: mr.CreatedAt,
	}
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
