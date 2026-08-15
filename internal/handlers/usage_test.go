package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/usage"
)

// stubUsage records the identity it was handed and answers with a canned
// view.
type stubUsage struct {
	read  aggregate.ReadContext
	view  usage.View
	err   error
	calls int
}

func (s *stubUsage) GetUsageView(_ context.Context, read aggregate.ReadContext) (usage.View, error) {
	s.read, s.calls = read, s.calls+1
	return s.view, s.err
}

func serveUsage(t *testing.T, h *UsageHandler, target string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	h.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder
}

func f(v float64) *float64 { return &v }

// The view is shaped field for field; a metered row carries its numbers, a
// DEFERRED row and a telemetry gap carry NO number at all — the JSON cannot
// render unmeasured usage as zero (SPEC-0041 AC2, AC3).
func TestUsageViewShapesCoverageAndGaps(t *testing.T) {
	start := time.Date(2026, 8, 15, 11, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	u := &stubUsage{view: usage.View{
		GeneratedAt: end,
		Dimensions: []usage.DimensionView{
			{Dimension: "CI_MINUTES", Coverage: "METERED", State: "WITHIN", Trend: "FLAT", Value: f(42), Envelope: f(10000), Notification: f(8000), Unit: "minutes", WindowStart: &start, WindowEnd: &end},
			{Dimension: "SEATS", Coverage: "DEFERRED", DeferredReason: "no authoritative telemetry source yet"},
			{Dimension: "EGRESS", Coverage: "METERED", TelemetryGap: true, Gaps: []usage.Gap{{WindowStart: start, WindowEnd: end, Reason: "no telemetry received"}}},
		},
		Divergences: []usage.Divergence{{Dimension: "CI_MINUTES", DataPlaneID: "plane-1", ControlPlane: 100, DataPlaneReport: 90, WindowStart: start, WindowEnd: end}},
	}}
	response := serveUsage(t, NewUsage(u, session()), "/api/v1/usage/view")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{
		`"dimension":"CI_MINUTES"`, `"value":42`, `"envelope":10000`, `"notification":8000`, `"trend":"FLAT"`,
		`"dimension":"SEATS"`, `"coverage":"DEFERRED"`, `"deferred_reason":"no authoritative telemetry source yet"`,
		`"dimension":"EGRESS"`, `"telemetry_gap":true`, `"reason":"no telemetry received"`,
		`"data_plane_id":"plane-1"`, `"control_plane_value":100`, `"data_plane_reported_value":90`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	// AC2/AC3: the SEATS and EGRESS rows marshal no numeric field at all.
	seats := body[strings.Index(body, `"dimension":"SEATS"`):strings.Index(body, `"dimension":"EGRESS"`)]
	for _, banned := range []string{`"value":`, `"envelope":`, `"window_start":`, `"state":`, `"trend":`} {
		if strings.Contains(seats, banned) {
			t.Fatalf("deferred row renders a number: %s", seats)
		}
	}
	egressIdx := strings.Index(body, `"dimension":"EGRESS"`)
	egress := body[egressIdx : egressIdx+strings.Index(body[egressIdx:], `"gaps"`)]
	if strings.Contains(egress, `"value":`) || strings.Contains(egress, `"window_start":`) || strings.Contains(egress, `"trend":`) {
		t.Fatalf("gap row renders a number or a trend: %s", egress)
	}
	// Identity came from the session, never from the request.
	if u.read.TenantID != "tenant-a" || u.read.ActorID != "actor-a" || u.read.RequestID == "" {
		t.Fatalf("usage context = %+v", u.read)
	}
}

// SPEC-0046 AC3: the throttle observation marshals with its metered and
// applied halves separate — absent entirely before an evaluation, the
// applied fields absent before an ack, and a failed ack marshals
// "applied":false with its error prose, never smoothed away.
func TestUsageViewThrottleObservationJSON(t *testing.T) {
	// No evaluation: the JSON carries no throttle key at all.
	u := &stubUsage{view: usage.View{Dimensions: []usage.DimensionView{}}}
	body := serveUsage(t, NewUsage(u, session()), "/api/v1/usage/view").Body.String()
	if strings.Contains(body, `"throttle"`) {
		t.Fatalf("an unevaluated tenant must marshal no throttle key: %s", body)
	}

	// Metered half only: no applied field may appear.
	u = &stubUsage{view: usage.View{
		Dimensions: []usage.DimensionView{},
		Throttle: usage.ThrottleObservation{
			Present: true, DesiredGeneration: 7, DesiredMaxCIConcurrency: 2, DesiredQueueDepthCap: 50,
		},
	}}
	body = serveUsage(t, NewUsage(u, session()), "/api/v1/usage/view").Body.String()
	for _, want := range []string{`"desired_generation":7`, `"desired_max_ci_concurrency":2`, `"desired_queue_depth_cap":50`, `"has_applied_ack":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	for _, banned := range []string{`"applied_generation"`, `"applied"`, `"acked_at"`} {
		if strings.Contains(body, banned) {
			t.Fatalf("unacked observation renders the applied half: %s", body)
		}
	}

	// Failed ack: applied:false and the error prose both marshal.
	acked := time.Date(2026, 8, 15, 12, 30, 0, 0, time.UTC)
	gen, applied := int64(7), false
	u = &stubUsage{view: usage.View{
		Dimensions: []usage.DimensionView{},
		Throttle: usage.ThrottleObservation{
			Present: true, DesiredGeneration: 7, DesiredMaxCIConcurrency: 2, DesiredQueueDepthCap: 50,
			HasAppliedAck: true, AppliedGeneration: gen, Applied: applied,
			AppliedError: "scaler unavailable", AckedAt: &acked,
		},
	}}
	body = serveUsage(t, NewUsage(u, session()), "/api/v1/usage/view").Body.String()
	for _, want := range []string{`"has_applied_ack":true`, `"applied_generation":7`, `"applied":false`, `"applied_error":"scaler unavailable"`, `"acked_at":`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
}

// A request without a session is refused and never reaches the backend.
func TestUsageViewWithoutSessionIsRefused(t *testing.T) {
	u := &stubUsage{}
	response := serveUsage(t, NewUsage(u, stubSession{}), "/api/v1/usage/view")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if u.calls != 0 {
		t.Fatal("backend was called without a session")
	}
}

// A backend refusal is the same coarse shape as everything else: no
// distinction between unauthorized, nonexistent, or unavailable
// (SPEC-0001).
func TestUsageViewBackendErrorIsCoarse(t *testing.T) {
	u := &stubUsage{err: errors.New("permission denied")}
	response := serveUsage(t, NewUsage(u, session()), "/api/v1/usage/view")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if strings.Contains(response.Body.String(), "permission") {
		t.Fatalf("refusal leaked the backend reason: %s", response.Body.String())
	}
}
