// policy.go is the policy visibility surface (T-0062, SPEC-0055, PR-16's read half).
//
// Reads only, and the absence is the design. ADR-0073 records that policy authoring is structural
// rather than missing: policies live in governance/ and ADR-0001 makes governance the Source of
// Truth, so a write here would be a second source of truth for the same decisions.
//
// There is therefore no write route, no draft route, and no route that accepts a policy and
// refuses it. A door that exists and says no is a promise; the product has not made one.
package handlers

import (
	"context"
	"net/http"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/policyview"
)

// PolicyReads is the policy read port this surface shapes.
type PolicyReads interface {
	BundleStatus(ctx context.Context, read aggregate.ReadContext) (policyview.BundleStatus, error)
	Decision(ctx context.Context, read aggregate.ReadContext, decisionID string) (policyview.DecisionRecord, error)
}

// PolicyHandler serves the policy read surface.
type PolicyHandler struct {
	policy  PolicyReads
	session Session
}

// NewPolicy wires the handler onto the read port.
func NewPolicy(policy PolicyReads, session Session) *PolicyHandler {
	return &PolicyHandler{policy: policy, session: session}
}

// BundleStatusView is the bundle in force. No policy source: the bundle is a platform artifact.
type BundleStatusView struct {
	BundleRevision string `json:"bundle_revision"`
	LoadedAt       string `json:"loaded_at"`
}

// DecisionRecordView is one recorded decision as a compliance reader consumes it.
type DecisionRecordView struct {
	DecisionID     string `json:"decision_id"`
	Action         string `json:"action"`
	ResourceType   string `json:"resource_type"`
	ResourceID     string `json:"resource_id"`
	Allowed        bool   `json:"allowed"`
	PolicyRevision string `json:"policy_revision"`
	InputDigest    string `json:"input_digest"`
	Mode           string `json:"mode"`
	DecidedAt      string `json:"decided_at"`
}

// Routes returns the policy read surface.
func (h *PolicyHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/policy/bundle", h.bundle)
	mux.HandleFunc("GET /api/v1/policy/decisions/{decision_id}", h.decision)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux.
func (h *PolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

func (h *PolicyHandler) bundle(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedPolicy(w)
		return
	}
	read.RequestID = newRequestID()
	status, err := h.policy.BundleStatus(r.Context(), read)
	if err != nil {
		deniedPolicy(w)
		return
	}
	writeJSON(w, BundleStatusView{BundleRevision: status.BundleRevision, LoadedAt: status.LoadedAt})
}

func (h *PolicyHandler) decision(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedPolicy(w)
		return
	}
	read.RequestID = newRequestID()
	record, err := h.policy.Decision(r.Context(), read, r.PathValue("decision_id"))
	if err != nil {
		deniedPolicy(w)
		return
	}
	writeJSON(w, DecisionRecordView{
		DecisionID: record.DecisionID, Action: record.Action,
		ResourceType: record.ResourceType, ResourceID: record.ResourceID,
		Allowed: record.Allowed, PolicyRevision: record.PolicyRevision,
		InputDigest: record.InputDigest, Mode: record.Mode, DecidedAt: record.DecidedAt,
	})
}

// deniedPolicy is the one refusal. A decision that does not exist and one belonging to another
// tenant reach it identically, which is what keeps a probe from enumerating either.
func deniedPolicy(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "policy unavailable", http.StatusNotFound)
}
