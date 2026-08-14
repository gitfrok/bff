// Package handlers serves BFF HTTP surfaces that shape and forward only
// (invariant 18).
//
// search.go is the Code Search surface (SPEC-0034, SPEC-0035, T-0028). The
// backend SearchService is the PDP for search.read and
// search.index.status.read: the searchable repository set is derived
// server-side at query time, counts are authorization-derived, and this
// surface performs no filtering, ranking, or authorization of its own
// (SPEC-0034 AC9). Its one addition is enrichment: each authorized match is
// joined with the file metadata Repository/Git serves for it, through the
// same RepositoryReader contract the browser uses — identity forwarded, and
// an enrichment failure degrades to no metadata rather than deciding
// anything about the result.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/search"
)

// Session resolves the verified identity a request runs under, as in the
// browser and mr packages.
type Session interface {
	ReadContext(*http.Request) (aggregate.ReadContext, bool)
}

// Searcher is the code search port this surface shapes. The backend owns
// every decision: scope, filtering, counts and cursors (SPEC-0035).
type Searcher interface {
	Search(ctx context.Context, read aggregate.ReadContext, q search.Query) (search.Page, error)
	IndexStatus(ctx context.Context, read aggregate.ReadContext) ([]search.IndexStatus, error)
}

// FileReader is the repository read port used for enrichment. Repository/Git
// is the repo.read enforcement point; this surface only reads paths the
// search backend already returned as authorized, forwarding the session's
// verified identity. A nil port serves results without metadata.
type FileReader interface {
	File(ctx context.Context, read aggregate.ReadContext, revision, path string, send func(aggregate.FileChunk) error) error
}

// SearchHandler serves the code search surface.
type SearchHandler struct {
	search  Searcher
	files   FileReader
	session Session
}

// NewSearch wires the handler onto the search port. files may be nil, in
// which case results carry no repository metadata.
func NewSearch(searcher Searcher, files FileReader, session Session) *SearchHandler {
	return &SearchHandler{search: searcher, files: files, session: session}
}

// Routes returns the search surface. Identity never comes from these paths
// or parameters — only from the authenticated session.
func (h *SearchHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/search/query", h.query)
	mux.HandleFunc("GET /api/v1/search/status", h.status)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux, as the
// mr handler does.
func (h *SearchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

// searchRequest is the JSON shape the web page posts. It mirrors the
// contract's SearchRequest minus everything the session supplies: no tenant,
// actor, role, or repository set is caller-assertable (SPEC-0035 AC2).
type searchRequest struct {
	Query            string `json:"query"`
	Mode             string `json:"mode"`
	ResultLimit      int32  `json:"result_limit"`
	ContextLineLimit int32  `json:"context_line_limit"`
	PageToken        string `json:"page_token"`
}

// FileMetadataView is the repository metadata one enriched match carries.
type FileMetadataView struct {
	Path      string `json:"path"`
	ObjectID  string `json:"object_id"`
	Mode      uint32 `json:"mode"`
	SizeBytes int64  `json:"size_bytes"`
}

// SearchResultView is one authorized match as the page consumes it. It
// carries no count, score, or permission fact.
type SearchResultView struct {
	RepositoryID   string            `json:"repository_id"`
	Revision       string            `json:"revision"`
	Path           string            `json:"path"`
	LineStart      int64             `json:"line_start"`
	LineEnd        int64             `json:"line_end"`
	MatchedContent string            `json:"matched_content"`
	Metadata       *FileMetadataView `json:"metadata,omitempty"`
}

// SearchPageView is the JSON shape the query endpoint returns. Results is
// never null so the empty page — the one shape a no-match query and an
// unauthorized-only query both produce — marshals identically every time
// (SPEC-0035 AC4).
type SearchPageView struct {
	Results       []SearchResultView `json:"results"`
	NextPageToken string             `json:"next_page_token"`
}

// IndexStatusView is one repository's freshness record as the page consumes it.
type IndexStatusView struct {
	RepositoryID        string    `json:"repository_id"`
	LastIndexedRevision string    `json:"last_indexed_revision"`
	IndexedAt           time.Time `json:"indexed_at"`
	FreshnessLagMS      int64     `json:"freshness_lag_ms"`
}

// IndexStatusPageView is the JSON shape the status endpoint returns.
type IndexStatusPageView struct {
	Entries []IndexStatusView `json:"entries"`
}

// maxSearchBodyBytes bounds the query body: a query is a handful of fields,
// and nothing legitimate approaches this.
const maxSearchBodyBytes = 64 << 10

func (h *SearchHandler) query(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		denied(w)
		return
	}
	var in searchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSearchBodyBytes)).Decode(&in); err != nil {
		denied(w)
		return
	}
	mode, ok := search.ModeOf(in.Mode)
	if !ok {
		denied(w)
		return
	}
	read.RequestID = newRequestID()
	page, err := h.search.Search(r.Context(), read, search.Query{
		Text:             in.Query,
		Mode:             mode,
		ResultLimit:      in.ResultLimit,
		ContextLineLimit: in.ContextLineLimit,
		PageToken:        in.PageToken,
	})
	if err != nil {
		denied(w)
		return
	}
	writeJSON(w, h.pageView(r.Context(), read, page))
}

func (h *SearchHandler) status(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		denied(w)
		return
	}
	read.RequestID = newRequestID()
	entries, err := h.search.IndexStatus(r.Context(), read)
	if err != nil {
		denied(w)
		return
	}
	view := IndexStatusPageView{Entries: make([]IndexStatusView, 0, len(entries))}
	for _, e := range entries {
		view.Entries = append(view.Entries, IndexStatusView{
			RepositoryID:        e.RepositoryID,
			LastIndexedRevision: e.LastIndexedRevision,
			IndexedAt:           e.IndexedAt,
			FreshnessLagMS:      e.FreshnessLag.Milliseconds(),
		})
	}
	writeJSON(w, view)
}

// pageView shapes the authorized page, joining each match with the file
// metadata Repository/Git serves. Order and membership come from the backend
// untouched: enrichment adds fields, it never removes or reorders results
// (invariant 18).
func (h *SearchHandler) pageView(ctx context.Context, read aggregate.ReadContext, page search.Page) SearchPageView {
	view := SearchPageView{Results: make([]SearchResultView, 0, len(page.Results)), NextPageToken: page.NextPageToken}
	type fileKey struct{ repository, revision, path string }
	seen := map[fileKey]*aggregate.FileMetadata{}
	for _, m := range page.Results {
		result := SearchResultView{
			RepositoryID:   m.RepositoryID,
			Revision:       m.Revision,
			Path:           m.Path,
			LineStart:      m.LineStart,
			LineEnd:        m.LineEnd,
			MatchedContent: m.MatchedContent,
		}
		key := fileKey{m.RepositoryID, m.Revision, m.Path}
		metadata, cached := seen[key]
		if !cached {
			metadata = h.fileMetadata(ctx, read, key.repository, key.revision, key.path)
			seen[key] = metadata
		}
		if metadata != nil {
			result.Metadata = &FileMetadataView{
				Path:      metadata.Path,
				ObjectID:  metadata.ObjectID,
				Mode:      metadata.Mode,
				SizeBytes: metadata.SizeBytes,
			}
		}
		view.Results = append(view.Results, result)
	}
	return view
}

// errMetadataTaken stops the file stream once its first frame has answered:
// enrichment wants the metadata, not the bytes.
var errMetadataTaken = errors.New("search: metadata taken")

// fileMetadata reads the one metadata frame Repository/Git serves for the
// matched path at the matched revision. A refusal or absence degrades to no
// metadata — enrichment never filters, so a result is never dropped here.
func (h *SearchHandler) fileMetadata(ctx context.Context, read aggregate.ReadContext, repositoryID, revision, path string) *aggregate.FileMetadata {
	if h.files == nil {
		return nil
	}
	enrich := read
	enrich.RepositoryID = repositoryID
	var metadata *aggregate.FileMetadata
	err := h.files.File(ctx, enrich, revision, path, func(chunk aggregate.FileChunk) error {
		metadata = chunk.Metadata
		return errMetadataTaken
	})
	if err != nil && !errors.Is(err, errMetadataTaken) {
		return nil
	}
	return metadata
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// denied is the one refusal this surface returns: it distinguishes nothing
// about what exists, what is allowed, or why (SPEC-0001).
func denied(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "search unavailable", http.StatusNotFound)
}

func newRequestID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}
