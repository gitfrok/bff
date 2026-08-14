// security.go is the Unified Security Dashboard surface (SPEC-0026,
// SPEC-0027, T-0023). The backend FindingsService is the PDP for
// findings.read, findings.summary.read and findings.triage: the caller's
// readable repository set is derived server-side inside every query, counts
// and facets are computed under that authorization, and this surface
// performs no filtering, aggregation, or authorization of its own
// (SPEC-0026 AC8). Triage is forwarded as a control action — the backend
// authorizes it, appends the immutable audit record, and answers with the
// record now in force; this surface only carries the decision and the
// session's verified identity across the wire.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/security"
)

// Security is the findings port this surface shapes. The backend owns every
// decision: scope, filtering, counts, facets and triage transitions
// (SPEC-0026, SPEC-0027).
type Security interface {
	ListFindings(ctx context.Context, read aggregate.ReadContext, f security.Filters, pageSize int32, pageToken string) (security.FindingPage, error)
	FindingsSummary(ctx context.Context, read aggregate.ReadContext, f security.Filters, dimensions []string) (security.Summary, error)
	SetTriage(ctx context.Context, read aggregate.ReadContext, in security.TriageRequest) (security.Triage, error)
}

// SecurityHandler serves the unified security dashboard surface.
type SecurityHandler struct {
	security Security
	session  Session
}

// NewSecurity wires the handler onto the findings port.
func NewSecurity(sec Security, session Session) *SecurityHandler {
	return &SecurityHandler{security: sec, session: session}
}

// Routes returns the dashboard surface. Identity never comes from these
// paths or parameters — only from the authenticated session.
func (h *SecurityHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/security/triage", h.triage)
	mux.HandleFunc("GET /api/v1/security/findings/summary", h.summary)
	mux.HandleFunc("GET /api/v1/security/dashboard", h.dashboard)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux, as the
// search handler does.
func (h *SecurityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

// triageRequest is the JSON shape the dashboard posts. It mirrors the
// contract's SetTriageRequest minus everything the session supplies or the
// server computes: no tenant, actor, or role is caller-assertable, and the
// request carries no severity, lifecycle state, or authorization flag
// (SPEC-0027).
type triageRequest struct {
	FindingID       string `json:"finding_id"`
	State           string `json:"state"`
	Justification   string `json:"justification"`
	ExpectedVersion int64  `json:"expected_version"`
}

// TriageView is the record now in force as the dashboard consumes it.
type TriageView struct {
	TriageID      string    `json:"triage_id"`
	FindingID     string    `json:"finding_id"`
	RepositoryID  string    `json:"repository_id"`
	State         string    `json:"state"`
	Justification string    `json:"justification"`
	Version       int64     `json:"version"`
	ActorID       string    `json:"actor_id"`
	OccurredAt    time.Time `json:"occurred_at"`
}

// FindingView is one authorized finding as the dashboard consumes it. It
// carries no count, permission fact, or authorization outcome.
type FindingView struct {
	FindingID           string `json:"finding_id"`
	RepositoryID        string `json:"repository_id"`
	ScannerClass        string `json:"scanner_class"`
	ToolName            string `json:"tool_name"`
	ToolVersion         string `json:"tool_version"`
	RuleID              string `json:"rule_id"`
	Severity            string `json:"severity"`
	Lifecycle           string `json:"lifecycle"`
	ArtifactPath        string `json:"artifact_path"`
	EnclosingContent    string `json:"enclosing_content"`
	Component           string `json:"component"`
	ComponentVersion    string `json:"component_version"`
	FirstSeenScanID     string `json:"first_seen_scan_id"`
	LastSeenScanID      string `json:"last_seen_scan_id"`
	Provenance          []byte `json:"provenance,omitempty"`
	ProvenanceMediaType string `json:"provenance_media_type,omitempty"`
}

// DashboardPageView is the JSON shape the dashboard endpoint returns.
// Findings is never null so the empty page — the one shape a no-match query
// and an unauthorized-only query both produce — marshals identically every
// time (SPEC-0026 AC6).
type DashboardPageView struct {
	Findings      []FindingView `json:"findings"`
	NextPageToken string        `json:"next_page_token"`
}

// FacetValueView is one value within a facet and the count of authorized
// findings carrying it.
type FacetValueView struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// FacetView is one requested dimension's authorized distribution.
type FacetView struct {
	Dimension string           `json:"dimension"`
	Values    []FacetValueView `json:"values"`
}

// SummaryView is the JSON shape the summary endpoint returns. TotalCount
// counts only findings the caller may read: the shape has no field capable
// of expressing an unauthorized total (SPEC-0027 AC4).
type SummaryView struct {
	TotalCount int64       `json:"total_count"`
	Facets     []FacetView `json:"facets"`
}

// maxTriageBodyBytes bounds the triage body: a decision is a handful of
// fields, and nothing legitimate approaches this.
const maxTriageBodyBytes = 64 << 10

func (h *SecurityHandler) triage(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedSecurity(w)
		return
	}
	var in triageRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTriageBodyBytes)).Decode(&in); err != nil {
		deniedSecurity(w)
		return
	}
	state, ok := security.StateOf(in.State)
	if !ok {
		deniedSecurity(w)
		return
	}
	read.RequestID = newRequestID()
	triage, err := h.security.SetTriage(r.Context(), read, security.TriageRequest{
		FindingID:       in.FindingID,
		State:           state,
		Justification:   in.Justification,
		ExpectedVersion: in.ExpectedVersion,
	})
	if err != nil {
		deniedSecurity(w)
		return
	}
	writeJSON(w, TriageView{
		TriageID:      triage.TriageID,
		FindingID:     triage.FindingID,
		RepositoryID:  triage.RepositoryID,
		State:         string(triage.State),
		Justification: triage.Justification,
		Version:       triage.Version,
		ActorID:       triage.ActorID,
		OccurredAt:    triage.OccurredAt,
	})
}

// dashboardFilters reads the dashboard filter set from the query string with
// the contract's UNSPECIFIED/empty/zero semantics: an absent parameter is
// no filter, and a filter the contract does not name is the same coarse
// refusal as everything else.
func dashboardFilters(r *http.Request) (security.Filters, int32, string, bool) {
	query := r.URL.Query()
	pageSize := int32(0)
	if raw := query.Get("page_size"); raw != "" {
		size, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return security.Filters{}, 0, "", false
		}
		pageSize = int32(size)
	}
	minAge, ok := ageBound(query.Get("min_age_days"))
	if !ok {
		return security.Filters{}, 0, "", false
	}
	maxAge, ok := ageBound(query.Get("max_age_days"))
	if !ok {
		return security.Filters{}, 0, "", false
	}
	filters := security.Filters{
		Repository:   query.Get("repository"),
		ScannerClass: query.Get("scanner_class"),
		Severity:     query.Get("severity"),
		Lifecycle:    query.Get("lifecycle"),
		MinAgeDays:   minAge,
		MaxAgeDays:   maxAge,
		OwningTeam:   query.Get("owning_team"),
	}
	// A filter the contract does not name is refused here, before anything
	// reaches the backend — the same coarse shape as every other refusal.
	return filters, pageSize, query.Get("page_token"), security.ValidateFilters(filters)
}

// ageBound parses one age bound; an empty bound leaves that side unbounded,
// as the contract names it.
func ageBound(raw string) (int32, bool) {
	if raw == "" {
		return 0, true
	}
	age, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, false
	}
	return int32(age), true
}

func (h *SecurityHandler) dashboard(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedSecurity(w)
		return
	}
	filters, pageSize, pageToken, ok := dashboardFilters(r)
	if !ok {
		deniedSecurity(w)
		return
	}
	read.RequestID = newRequestID()
	page, err := h.security.ListFindings(r.Context(), read, filters, pageSize, pageToken)
	if err != nil {
		deniedSecurity(w)
		return
	}
	view := DashboardPageView{Findings: make([]FindingView, 0, len(page.Findings)), NextPageToken: page.NextPageToken}
	for _, f := range page.Findings {
		view.Findings = append(view.Findings, FindingView{
			FindingID:           f.FindingID,
			RepositoryID:        f.RepositoryID,
			ScannerClass:        f.ScannerClass,
			ToolName:            f.ToolName,
			ToolVersion:         f.ToolVersion,
			RuleID:              f.RuleID,
			Severity:            f.Severity,
			Lifecycle:           f.Lifecycle,
			ArtifactPath:        f.ArtifactPath,
			EnclosingContent:    f.EnclosingContent,
			Component:           f.Component,
			ComponentVersion:    f.ComponentVersion,
			FirstSeenScanID:     f.FirstSeenScanID,
			LastSeenScanID:      f.LastSeenScanID,
			Provenance:          f.Provenance,
			ProvenanceMediaType: f.ProvenanceMediaType,
		})
	}
	writeJSON(w, view)
}

func (h *SecurityHandler) summary(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedSecurity(w)
		return
	}
	filters, _, _, ok := dashboardFilters(r)
	if !ok {
		deniedSecurity(w)
		return
	}
	read.RequestID = newRequestID()
	summary, err := h.security.FindingsSummary(r.Context(), read, filters, r.URL.Query()["facet"])
	if err != nil {
		deniedSecurity(w)
		return
	}
	view := SummaryView{TotalCount: summary.TotalCount, Facets: make([]FacetView, 0, len(summary.Facets))}
	for _, facet := range summary.Facets {
		shaped := FacetView{Dimension: facet.Dimension, Values: make([]FacetValueView, 0, len(facet.Values))}
		for _, value := range facet.Values {
			shaped.Values = append(shaped.Values, FacetValueView{Value: value.Value, Count: value.Count})
		}
		view.Facets = append(view.Facets, shaped)
	}
	writeJSON(w, view)
}

// deniedSecurity is the one refusal this surface returns: it distinguishes
// nothing about what exists, what is allowed, or why (SPEC-0001).
func deniedSecurity(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "security unavailable", http.StatusNotFound)
}
