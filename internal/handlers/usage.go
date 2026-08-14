// usage.go is the fair-use usage view surface (SPEC-0041, T-0034). The
// backend UsageService is the metering authority and the PDP for
// usage.view.read (ADR-0061): the numbers this surface returns are the same
// counters every envelope decision is made from, coverage and gaps are the
// backend's statement, and this surface performs no computation, adjustment,
// or authorization of its own (invariant 18). Unmeasured usage has no
// representation here: a DEFERRED dimension or a telemetry gap omits its
// number entirely — it can never render as zero (SPEC-0041 AC2, AC3).
package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/usage"
)

// Usage is the usage port this surface shapes. The backend owns every
// number, every coverage statement and every gap (SPEC-0041).
type Usage interface {
	GetUsageView(ctx context.Context, read aggregate.ReadContext) (usage.View, error)
}

// UsageHandler serves the usage view surface.
type UsageHandler struct {
	usage   Usage
	session Session
}

// NewUsage wires the handler onto the usage port.
func NewUsage(u Usage, session Session) *UsageHandler {
	return &UsageHandler{usage: u, session: session}
}

// Routes returns the usage surface. Identity never comes from these paths
// or parameters — only from the authenticated session.
func (h *UsageHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/usage/view", h.view)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux.
func (h *UsageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

// UsageGapView is one telemetry-less interval (SPEC-0041 AC3).
type UsageGapView struct {
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Reason      string    `json:"reason"`
}

// UsageDimensionView is one PRD §6 dimension's row as the browser consumes
// it. The numeric fields are pointers marshalled with omitempty: a deferred
// dimension or a telemetry gap marshals NO number at all, so a client
// cannot mistake "unmeasured" for zero (SPEC-0041 AC2, AC3).
type UsageDimensionView struct {
	Dimension      string         `json:"dimension"`
	Coverage       string         `json:"coverage"`
	State          string         `json:"state,omitempty"`
	Value          *float64       `json:"value,omitempty"`
	Envelope       *float64       `json:"envelope,omitempty"`
	Notification   *float64       `json:"notification,omitempty"`
	Unit           string         `json:"unit,omitempty"`
	WindowStart    *time.Time     `json:"window_start,omitempty"`
	WindowEnd      *time.Time     `json:"window_end,omitempty"`
	TelemetryGap   bool           `json:"telemetry_gap,omitempty"`
	Gaps           []UsageGapView `json:"gaps"`
	DeferredReason string         `json:"deferred_reason,omitempty"`
}

// UsageDivergenceView is one health finding: both numbers are shown and the
// control plane's counter is labelled authoritative (SPEC-0041 AC1,
// ADR-0061 §2).
type UsageDivergenceView struct {
	Dimension       string    `json:"dimension"`
	DataPlaneID     string    `json:"data_plane_id"`
	ControlPlane    float64   `json:"control_plane_value"`
	DataPlaneReport float64   `json:"data_plane_reported_value"`
	WindowStart     time.Time `json:"window_start"`
	WindowEnd       time.Time `json:"window_end"`
}

// UsageViewResponse is the JSON shape the usage endpoint returns.
// Dimensions is never null: the list itself is the coverage statement
// (SPEC-0041 AC2).
type UsageViewResponse struct {
	Dimensions  []UsageDimensionView  `json:"dimensions"`
	Divergences []UsageDivergenceView `json:"divergences"`
	GeneratedAt time.Time             `json:"generated_at"`
}

func (h *UsageHandler) view(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedUsage(w)
		return
	}
	read.RequestID = newRequestID()
	view, err := h.usage.GetUsageView(r.Context(), read)
	if err != nil {
		deniedUsage(w)
		return
	}
	response := UsageViewResponse{
		Dimensions:  make([]UsageDimensionView, 0, len(view.Dimensions)),
		Divergences: make([]UsageDivergenceView, 0, len(view.Divergences)),
		GeneratedAt: view.GeneratedAt,
	}
	for _, d := range view.Dimensions {
		row := UsageDimensionView{
			Dimension:      d.Dimension,
			Coverage:       d.Coverage,
			State:          d.State,
			Value:          d.Value,
			Envelope:       d.Envelope,
			Notification:   d.Notification,
			Unit:           d.Unit,
			WindowStart:    d.WindowStart,
			WindowEnd:      d.WindowEnd,
			TelemetryGap:   d.TelemetryGap,
			Gaps:           make([]UsageGapView, 0, len(d.Gaps)),
			DeferredReason: d.DeferredReason,
		}
		for _, g := range d.Gaps {
			row.Gaps = append(row.Gaps, UsageGapView{WindowStart: g.WindowStart, WindowEnd: g.WindowEnd, Reason: g.Reason})
		}
		response.Dimensions = append(response.Dimensions, row)
	}
	for _, dv := range view.Divergences {
		response.Divergences = append(response.Divergences, UsageDivergenceView{
			Dimension:       dv.Dimension,
			DataPlaneID:     dv.DataPlaneID,
			ControlPlane:    dv.ControlPlane,
			DataPlaneReport: dv.DataPlaneReport,
			WindowStart:     dv.WindowStart,
			WindowEnd:       dv.WindowEnd,
		})
	}
	writeJSON(w, response)
}

// deniedUsage is the one refusal this surface returns: it distinguishes
// nothing about what exists, what is allowed, or why (SPEC-0001).
func deniedUsage(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "usage unavailable", http.StatusNotFound)
}
