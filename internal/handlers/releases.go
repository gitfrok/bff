// releases.go is the release surface (T-0065, SPEC-0056, PR-29's accepted increment).
//
// It shapes and forwards. There is no artifact route, no upload route and no download route —
// ADR-0075 accepted tags and notes only, and a door that exists and refuses is a promise nobody has
// made.
package handlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/releases"
)

// Releases is the release port this surface shapes.
type Releases interface {
	Tags(ctx context.Context, read aggregate.ReadContext, pageToken string, pageSize int32) ([]releases.Tag, string, error)
	Publish(ctx context.Context, read aggregate.ReadContext, tag, notes string) (releases.Release, error)
	Get(ctx context.Context, read aggregate.ReadContext, tag string) (releases.Release, error)
	List(ctx context.Context, read aggregate.ReadContext, pageToken string, pageSize int32) ([]releases.Release, string, error)
	UpdateNotes(ctx context.Context, read aggregate.ReadContext, tag, notes string) (releases.Release, error)
}

// ReleasesHandler serves the release surface.
type ReleasesHandler struct {
	releases Releases
	session  Session
}

// NewReleases wires the handler onto the release port.
func NewReleases(r Releases, session Session) *ReleasesHandler {
	return &ReleasesHandler{releases: r, session: session}
}

// TagView is a tag and what it points at now.
type TagView struct {
	Name     string `json:"name"`
	CommitID string `json:"commit_id"`
}

// TagListView is the tag list.
type TagListView struct {
	Tags          []TagView `json:"tags"`
	NextPageToken string    `json:"next_page_token"`
}

// ReleaseView is the record. published_commit is what the tag pointed at when published; the
// reader compares it with the tag's current target, which is why both travel.
type ReleaseView struct {
	Tag             string `json:"tag"`
	PublishedCommit string `json:"published_commit"`
	Notes           string `json:"notes"`
	PublishedBy     string `json:"published_by"`
	PublishedAt     string `json:"published_at"`
	NotesUpdatedAt  string `json:"notes_updated_at"`
}

// ReleaseListView is a page of releases. No total, and no artifact.
type ReleaseListView struct {
	Releases      []ReleaseView `json:"releases"`
	NextPageToken string        `json:"next_page_token"`
}

const maxReleasePageSize = 200

// Routes returns the release surface.
func (h *ReleasesHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/repositories/{repository_id}/tags", h.tags)
	mux.HandleFunc("GET /v1/repositories/{repository_id}/releases", h.list)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/releases", h.publish)
	mux.HandleFunc("GET /v1/repositories/{repository_id}/releases/{tag}", h.get)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/releases/{tag}/notes", h.updateNotes)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux.
func (h *ReleasesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

func (h *ReleasesHandler) begin(w http.ResponseWriter, r *http.Request) (aggregate.ReadContext, bool) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedReleases(w)
		return aggregate.ReadContext{}, false
	}
	read.RepositoryID = r.PathValue("repository_id")
	if read.RepositoryID == "" {
		deniedReleases(w)
		return aggregate.ReadContext{}, false
	}
	read.RequestID = newRequestID()
	return read, true
}

func releasePageSize(raw string, w http.ResponseWriter) (int32, bool) {
	if raw == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || n < 0 {
		deniedReleases(w)
		return 0, false
	}
	if n > maxReleasePageSize {
		n = maxReleasePageSize
	}
	return int32(n), true
}

func (h *ReleasesHandler) tags(w http.ResponseWriter, r *http.Request) {
	read, ok := h.begin(w, r)
	if !ok {
		return
	}
	size, ok := releasePageSize(r.URL.Query().Get("page_size"), w)
	if !ok {
		return
	}
	tags, next, err := h.releases.Tags(r.Context(), read, r.URL.Query().Get("page_token"), size)
	if err != nil {
		deniedReleases(w)
		return
	}
	view := TagListView{Tags: make([]TagView, 0, len(tags)), NextPageToken: next}
	for _, t := range tags {
		view.Tags = append(view.Tags, TagView{Name: t.Name, CommitID: t.CommitID})
	}
	writeJSON(w, view)
}

func (h *ReleasesHandler) list(w http.ResponseWriter, r *http.Request) {
	read, ok := h.begin(w, r)
	if !ok {
		return
	}
	size, ok := releasePageSize(r.URL.Query().Get("page_size"), w)
	if !ok {
		return
	}
	found, next, err := h.releases.List(r.Context(), read, r.URL.Query().Get("page_token"), size)
	if err != nil {
		deniedReleases(w)
		return
	}
	view := ReleaseListView{Releases: make([]ReleaseView, 0, len(found)), NextPageToken: next}
	for _, rel := range found {
		view.Releases = append(view.Releases, releaseView(rel))
	}
	writeJSON(w, view)
}

func (h *ReleasesHandler) get(w http.ResponseWriter, r *http.Request) {
	read, ok := h.begin(w, r)
	if !ok {
		return
	}
	record, err := h.releases.Get(r.Context(), read, r.PathValue("tag"))
	if err != nil {
		deniedReleases(w)
		return
	}
	writeJSON(w, releaseView(record))
}

// publish takes a form, as every other write on this frontend's behalf does.
func (h *ReleasesHandler) publish(w http.ResponseWriter, r *http.Request) {
	read, ok := h.begin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		deniedReleases(w)
		return
	}
	record, err := h.releases.Publish(r.Context(), read, r.PostFormValue("tag"), r.PostFormValue("notes"))
	if err != nil {
		// The one distinguished outcome: a conflict with a state the caller can already see.
		if errors.Is(err, releases.ErrAlreadyPublished) {
			w.Header().Set("Cache-Control", "private, no-store")
			http.Error(w, "this tag already has a release", http.StatusConflict)
			return
		}
		deniedReleases(w)
		return
	}
	writeJSON(w, releaseView(record))
}

func (h *ReleasesHandler) updateNotes(w http.ResponseWriter, r *http.Request) {
	read, ok := h.begin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		deniedReleases(w)
		return
	}
	record, err := h.releases.UpdateNotes(r.Context(), read, r.PathValue("tag"), r.PostFormValue("notes"))
	if err != nil {
		deniedReleases(w)
		return
	}
	writeJSON(w, releaseView(record))
}

func releaseView(r releases.Release) ReleaseView {
	return ReleaseView{
		Tag: r.Tag, PublishedCommit: r.PublishedCommit, Notes: r.Notes,
		PublishedBy: r.PublishedBy, PublishedAt: r.PublishedAt, NotesUpdatedAt: r.NotesUpdatedAt,
	}
}

// deniedReleases is the one refusal. An empty release list does not reach it: a repository with no
// releases is a successful, empty answer.
func deniedReleases(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "releases unavailable", http.StatusNotFound)
}
