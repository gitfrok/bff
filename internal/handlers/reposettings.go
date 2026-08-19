// reposettings.go is the repository settings surface (T-0069, SPEC-0057, PR-30's accepted increment).
//
// It shapes and forwards. There is no visibility route, no members route and no delete route —
// ADR-0076 accepted name, description and archival, and a door that exists and refuses is a promise
// nobody has made.
package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/reposettings"
)

// RepoSettings is the settings port this surface shapes.
type RepoSettings interface {
	Get(ctx context.Context, read aggregate.ReadContext) (reposettings.Settings, error)
	Update(ctx context.Context, read aggregate.ReadContext, name, description string) (reposettings.Settings, error)
	SetArchived(ctx context.Context, read aggregate.ReadContext, archived bool) (reposettings.Settings, error)
}

// RepoSettingsHandler serves the settings surface.
type RepoSettingsHandler struct {
	settings RepoSettings
	session  Session
}

// NewRepoSettings wires the handler onto the settings port.
func NewRepoSettings(s RepoSettings, session Session) *RepoSettingsHandler {
	return &RepoSettingsHandler{settings: s, session: session}
}

// SettingsView is what the browser reads.
//
// archived_at is empty when the repository is not archived, and there is no `archived` boolean beside
// it: the reader decides what to render from the instant's presence, so the two cannot disagree.
//
// There is no visibility, member, role, branch_protection or required_approvals field. That is
// ADR-0076's decision, and a test asserts the serialized body carries none of that vocabulary — the
// gate holds at the layer a browser actually reads, not only in the contract.
type SettingsView struct {
	RepositoryID      string `json:"repository_id"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	ArchivedAt        string `json:"archived_at"`
	SettingsUpdatedAt string `json:"settings_updated_at"`
	SettingsUpdatedBy string `json:"settings_updated_by"`
}

// Routes returns the settings surface.
func (h *RepoSettingsHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/repositories/{repository_id}/settings", h.get)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/settings", h.update)
	mux.HandleFunc("POST /v1/repositories/{repository_id}/settings/archive", h.archive)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux.
func (h *RepoSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

func (h *RepoSettingsHandler) begin(w http.ResponseWriter, r *http.Request) (aggregate.ReadContext, bool) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedSettings(w)
		return aggregate.ReadContext{}, false
	}
	read.RepositoryID = r.PathValue("repository_id")
	if read.RepositoryID == "" {
		deniedSettings(w)
		return aggregate.ReadContext{}, false
	}
	read.RequestID = newRequestID()
	return read, true
}

func (h *RepoSettingsHandler) get(w http.ResponseWriter, r *http.Request) {
	read, ok := h.begin(w, r)
	if !ok {
		return
	}
	settings, err := h.settings.Get(r.Context(), read)
	if err != nil {
		deniedSettings(w)
		return
	}
	writeJSON(w, settingsView(settings))
}

// update takes a form, as every other write on this frontend's behalf does.
func (h *RepoSettingsHandler) update(w http.ResponseWriter, r *http.Request) {
	read, ok := h.begin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		deniedSettings(w)
		return
	}
	settings, err := h.settings.Update(r.Context(), read, r.PostFormValue("name"), r.PostFormValue("description"))
	if err != nil {
		// The one distinguished outcome: the caller sent an empty name, which the caller can
		// already see. Everything else is the same coarse refusal.
		if errors.Is(err, reposettings.ErrNameRequired) {
			w.Header().Set("Cache-Control", "private, no-store")
			http.Error(w, "a repository needs a name", http.StatusBadRequest)
			return
		}
		deniedSettings(w)
		return
	}
	writeJSON(w, settingsView(settings))
}

// archive sets or clears the archived label.
//
// The form says which state is wanted rather than which transition to perform, so a resubmitted form
// is not an error and does not toggle anything — a toggle route would make a double-submit flip the
// state, and a person cannot tell a slow response from a lost one.
func (h *RepoSettingsHandler) archive(w http.ResponseWriter, r *http.Request) {
	read, ok := h.begin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		deniedSettings(w)
		return
	}
	settings, err := h.settings.SetArchived(r.Context(), read, r.PostFormValue("archived") == "true")
	if err != nil {
		deniedSettings(w)
		return
	}
	writeJSON(w, settingsView(settings))
}

func settingsView(s reposettings.Settings) SettingsView {
	return SettingsView{
		RepositoryID: s.RepositoryID, Name: s.Name, Description: s.Description,
		ArchivedAt:        s.ArchivedAt,
		SettingsUpdatedAt: s.SettingsUpdatedAt,
		SettingsUpdatedBy: s.SettingsUpdatedBy,
	}
}

// deniedSettings is the one refusal. It names no cause: whether the repository exists, whether the
// caller may administer it, and whether the backend answered are indistinguishable here.
func deniedSettings(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "repository settings unavailable", http.StatusNotFound)
}
