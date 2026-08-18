// repositories.go is the repository list surface (T-0054, SPEC-0052, PR-24).
//
// It shapes and forwards. The backend's Repository context is the enforcement point for
// `repo.read`, so there is no PDP here — a second decision at this layer would be a second answer
// to a question that already has one.
//
// The identity a request runs under comes only from the authenticated session. There is no query
// parameter, header or path segment through which a caller can name a tenant, an actor, a role,
// a repository set or a scope, because the contract below defines none.
package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/repositoryregistry"
)

// Registry is the listing port this surface shapes.
type Registry interface {
	List(ctx context.Context, read aggregate.ReadContext, pageToken string, pageSize int32) (repositoryregistry.Page, error)
}

// RepositoriesHandler serves the repository list.
type RepositoriesHandler struct {
	registry Registry
	session  Session
}

// NewRepositories wires the handler onto the registry port.
func NewRepositories(registry Registry, session Session) *RepositoriesHandler {
	return &RepositoriesHandler{registry: registry, session: session}
}

// RepositorySummaryView is one repository as the page consumes it.
type RepositorySummaryView struct {
	RepositoryID string `json:"repository_id"`
	Name         string `json:"name"`
}

// RepositoryListView is the JSON the list endpoint returns.
//
// Repositories is never null, so the empty page — the one shape a tenant with no repositories and
// a caller who may see none both produce — marshals identically every time. There is no total,
// and no field here could carry one.
type RepositoryListView struct {
	Repositories  []RepositorySummaryView `json:"repositories"`
	NextPageToken string                  `json:"next_page_token"`
}

// maxPageSize bounds one page of work. It is not reported and implies nothing about how many
// repositories exist.
const maxRepositoryPageSize = 200

// Routes returns the repository list surface.
func (h *RepositoriesHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/repositories", h.list)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux.
func (h *RepositoriesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

func (h *RepositoriesHandler) list(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedRepositories(w)
		return
	}
	// A list names no repository, so anything a caller put in that field is dropped rather than
	// forwarded: the contract has nowhere to carry it, and passing it along would invite someone
	// to start honouring it.
	read.RepositoryID = ""
	read.RequestID = newRequestID()

	pageSize := int32(0)
	if raw := r.URL.Query().Get("page_size"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || n < 0 {
			deniedRepositories(w)
			return
		}
		if n > maxRepositoryPageSize {
			n = maxRepositoryPageSize
		}
		pageSize = int32(n)
	}

	page, err := h.registry.List(r.Context(), read, r.URL.Query().Get("page_token"), pageSize)
	if err != nil {
		deniedRepositories(w)
		return
	}

	view := RepositoryListView{
		Repositories:  make([]RepositorySummaryView, 0, len(page.Repositories)),
		NextPageToken: page.NextPageToken,
	}
	for _, repo := range page.Repositories {
		view.Repositories = append(view.Repositories, RepositorySummaryView{
			RepositoryID: repo.RepositoryID, Name: repo.Name,
		})
	}
	writeJSON(w, view)
}

// deniedRepositories is the one refusal this surface returns. Note what does NOT reach it: a
// caller who may see no repositories gets an empty list with a 200, because "you may see none"
// and "there are none" have to be the same answer (SPEC-0052 AC4).
func deniedRepositories(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "repositories unavailable", http.StatusNotFound)
}
