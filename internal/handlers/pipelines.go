// pipelines.go is the pipeline runs surface (T-0060, SPEC-0054, PR-26's runs half).
//
// It shapes and forwards. The backend's CI context is the enforcement point; there is no PDP here.
//
// What this surface does NOT serve is job output. ADR-0072 defers retaining it to its own decision,
// and there is no route for it here — not a stub, not a 501, not a link. A door that exists and
// refuses is a promise; there is nothing to promise yet.
package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/pipelines"
)

// Runs is the pipeline listing port this surface shapes.
type Runs interface {
	List(ctx context.Context, read aggregate.ReadContext, repositoryID, pageToken string, pageSize int32) (pipelines.Page, error)
}

// PipelinesHandler serves the runs list.
type PipelinesHandler struct {
	runs    Runs
	session Session
}

// NewPipelines wires the handler onto the runs port.
func NewPipelines(runs Runs, session Session) *PipelinesHandler {
	return &PipelinesHandler{runs: runs, session: session}
}

// RunView is one run as the page consumes it. There is no log field, and no link to one.
type RunView struct {
	JobID          string `json:"job_id"`
	RepositoryID   string `json:"repository_id"`
	Ref            string `json:"ref"`
	CommitSHA      string `json:"commit_sha"`
	Trigger        string `json:"trigger"`
	State          string `json:"state"`
	QueuedAt       string `json:"queued_at"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at"`
	OutcomeSummary string `json:"outcome_summary"`
}

// RunListView is the JSON the list endpoint returns. Runs is never null, so the empty page — the
// one shape a caller who may see none and a repository with none both produce — marshals
// identically every time. No total.
type RunListView struct {
	Runs          []RunView `json:"runs"`
	NextPageToken string    `json:"next_page_token"`
}

const maxRunPageSize = 200

// Routes returns the runs surface.
func (h *PipelinesHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/pipelines/runs", h.list)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux.
func (h *PipelinesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

func (h *PipelinesHandler) list(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedPipelines(w)
		return
	}
	read.RequestID = newRequestID()

	pageSize := int32(0)
	if raw := r.URL.Query().Get("page_size"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || n < 0 {
			deniedPipelines(w)
			return
		}
		if n > maxRunPageSize {
			n = maxRunPageSize
		}
		pageSize = int32(n)
	}

	page, err := h.runs.List(r.Context(), read, r.URL.Query().Get("repository_id"),
		r.URL.Query().Get("page_token"), pageSize)
	if err != nil {
		deniedPipelines(w)
		return
	}

	view := RunListView{Runs: make([]RunView, 0, len(page.Runs)), NextPageToken: page.NextPageToken}
	for _, run := range page.Runs {
		view.Runs = append(view.Runs, RunView{
			JobID: run.JobID, RepositoryID: run.RepositoryID, Ref: run.Ref, CommitSHA: run.CommitSHA,
			Trigger: run.Trigger, State: run.State, QueuedAt: run.QueuedAt, StartedAt: run.StartedAt,
			FinishedAt: run.FinishedAt, OutcomeSummary: run.OutcomeSummary,
		})
	}
	writeJSON(w, view)
}

// deniedPipelines is the one refusal. A caller who may see no runs does not reach it: an empty list
// is a success, because "you may see none" and "there are none" are the same answer.
func deniedPipelines(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "pipelines unavailable", http.StatusNotFound)
}
