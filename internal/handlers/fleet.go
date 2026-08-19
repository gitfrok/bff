// fleet.go is the admin area's fleet report route (T-0072, SPEC-0058, PR-31's
// accepted increment).
//
// It shapes and forwards. There is no audit route beside it, no members route and
// no per-person field — ADR-0077 accepted a dated fleet report and a door into the
// grant flow, and the audit log is reached through a grant rather than through a
// role.
package handlers

import (
	"context"
	"net/http"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/fleet"
)

// Fleet is the fleet port this surface shapes.
type Fleet interface {
	List(ctx context.Context, read aggregate.ReadContext) ([]fleet.Plane, error)
}

// FleetHandler serves the fleet report.
type FleetHandler struct {
	fleet   Fleet
	session Session
}

// NewFleet wires the handler onto the fleet port.
func NewFleet(f Fleet, session Session) *FleetHandler {
	return &FleetHandler{fleet: f, session: session}
}

// PlaneView is one row of the report.
//
// last_seen_at is the field a reader must see: the data plane's connection is
// outbound-only, so this is a report with an age rather than live truth. It is
// empty for a plane that has never connected, and there is no boolean beside it
// that could disagree.
//
// There is no member, no user and no last_active field. That is ADR-0077's
// answer to its own follow-up: presence telemetry about people is not something
// this product collects, and a field that exists gets used.
type PlaneView struct {
	DataPlaneID          string `json:"data_plane_id"`
	Status               string `json:"status"`
	Cloud                string `json:"cloud"`
	Region               string `json:"region"`
	AgentVersion         string `json:"agent_version"`
	K8sVersion           string `json:"k8s_version"`
	LastSeenAt           string `json:"last_seen_at"`
	EnrolledAt           string `json:"enrolled_at"`
	CertificateExpiresAt string `json:"certificate_expires_at"`
	TokenID              string `json:"token_id"`
}

// FleetView is the report. It carries no total and no count of anything the caller
// cannot see.
type FleetView struct {
	Planes []PlaneView `json:"planes"`
}

// Routes returns the fleet surface.
func (h *FleetHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/admin/fleet", h.list)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux.
func (h *FleetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

func (h *FleetHandler) list(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedFleet(w)
		return
	}
	read.RequestID = newRequestID()

	planes, err := h.fleet.List(r.Context(), read)
	if err != nil {
		// Including the door not being configured. An unavailable report and an
		// empty fleet are different facts, and a 200 with no planes would assert
		// the second when only the first is known.
		deniedFleet(w)
		return
	}
	view := FleetView{Planes: make([]PlaneView, 0, len(planes))}
	for _, p := range planes {
		view.Planes = append(view.Planes, PlaneView{
			DataPlaneID: p.DataPlaneID, Status: p.Status, Cloud: p.Cloud, Region: p.Region,
			AgentVersion: p.AgentVersion, K8sVersion: p.K8sVersion,
			LastSeenAt: p.LastSeenAt, EnrolledAt: p.EnrolledAt,
			CertificateExpiresAt: p.CertificateExpiresAt, TokenID: p.TokenID,
		})
	}
	writeJSON(w, view)
}

// deniedFleet is the one refusal. It names no cause: whether the caller may read
// the fleet, whether the door is configured and whether the control plane answered
// are indistinguishable here.
func deniedFleet(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "fleet report unavailable", http.StatusNotFound)
}
