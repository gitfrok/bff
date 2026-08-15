package usage

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/gitfrok/bff/gen/proto/agent/v1"
	usagev1 "github.com/gitfrok/bff/gen/proto/usage/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeService records what crossed the wire and answers with a canned view.
type fakeService struct {
	req  *usagev1.GetUsageViewRequest
	resp *usagev1.GetUsageViewResponse
	err  error
}

func (f *fakeService) GetUsageView(_ context.Context, req *usagev1.GetUsageViewRequest, _ ...grpc.CallOption) (*usagev1.GetUsageViewResponse, error) {
	f.req = req
	return f.resp, f.err
}

func read() aggregate.ReadContext {
	return aggregate.ReadContext{
		TenantID: "tenant-a", ActorID: "actor-a", RequestID: "request-a",
		ActorRoles: []string{"member"},
	}
}

// The wire context carries exactly the session's verified identity — the
// usage view has no field a request could use to assert a tenant, a number,
// or a permission claim (SPEC-0041 AC10, SPEC-0001).
func TestGetUsageViewForwardsIdentityOnly(t *testing.T) {
	f := &fakeService{resp: &usagev1.GetUsageViewResponse{}}
	_, err := New(f).GetUsageView(context.Background(), read())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	ctx := f.req.GetContext()
	if ctx.GetTenantId() != "tenant-a" || ctx.GetActorId() != "actor-a" || ctx.GetRequestId() != "request-a" {
		t.Fatalf("context = %v", ctx)
	}
	//arch:allow-inline-authz this compares a forwarded role string for equality in a test; it grants nothing
	if got := ctx.GetActorRoles(); len(got) != 1 || got[0] != "member" {
		t.Fatalf("actor roles = %v", got)
	}
}

// A metered row without a gap carries its numbers and window; a DEFERRED
// row and a gapped row carry NO number at all — the adapter makes it
// structurally impossible to render unmeasured usage as zero (SPEC-0041
// AC2, AC3).
func TestGetUsageViewShapesCoverageAndGaps(t *testing.T) {
	start := time.Date(2026, 8, 15, 11, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	f := &fakeService{resp: &usagev1.GetUsageViewResponse{
		GeneratedAt: timestamppb.New(end),
		Dimensions: []*usagev1.UsageDimensionView{
			{
				Dimension:    agentv1.FairUseDimension_FAIR_USE_DIMENSION_CI_MINUTES,
				Coverage:     usagev1.DimensionCoverage_DIMENSION_COVERAGE_METERED,
				State:        agentv1.EnvelopeState_ENVELOPE_STATE_WITHIN,
				Trend:        usagev1.EnvelopeTrend_ENVELOPE_TREND_FLAT,
				CurrentValue: 42, EnvelopeValue: 10000, NotificationValue: 8000,
				Unit: "minutes", WindowStart: timestamppb.New(start), WindowEnd: timestamppb.New(end),
			},
			{
				Dimension:      agentv1.FairUseDimension_FAIR_USE_DIMENSION_SEATS,
				Coverage:       usagev1.DimensionCoverage_DIMENSION_COVERAGE_DEFERRED,
				DeferredReason: "no authoritative telemetry source yet",
			},
			{
				Dimension:    agentv1.FairUseDimension_FAIR_USE_DIMENSION_EGRESS,
				Coverage:     usagev1.DimensionCoverage_DIMENSION_COVERAGE_METERED,
				TelemetryGap: true,
				Gaps:         []*usagev1.UsageGap{{WindowStart: timestamppb.New(start), WindowEnd: timestamppb.New(end), Reason: "no telemetry received"}},
			},
		},
		Divergences: []*usagev1.UsageDivergence{{
			Dimension:   agentv1.FairUseDimension_FAIR_USE_DIMENSION_CI_MINUTES,
			DataPlaneId: "plane-1", ControlPlaneValue: 100, DataPlaneReportedValue: 90,
			WindowStart: timestamppb.New(start), WindowEnd: timestamppb.New(end),
		}},
	}}
	view, err := New(f).GetUsageView(context.Background(), read())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(view.Dimensions) != 3 {
		t.Fatalf("dimensions = %d, want 3", len(view.Dimensions))
	}

	ci := view.Dimensions[0]
	if ci.Dimension != "CI_MINUTES" || ci.Coverage != "METERED" || ci.State != "WITHIN" {
		t.Fatalf("metered row = %+v", ci)
	}
	// SPEC-0046 AC2: the metered row carries the wire's trend untouched.
	if ci.Trend != "FLAT" {
		t.Fatalf("metered trend = %q, want FLAT", ci.Trend)
	}
	if ci.Value == nil || *ci.Value != 42 || ci.Envelope == nil || *ci.Envelope != 10000 || ci.Notification == nil || *ci.Notification != 8000 {
		t.Fatalf("metered numbers = %+v/%+v/%+v", ci.Value, ci.Envelope, ci.Notification)
	}
	if ci.WindowStart == nil || ci.WindowEnd == nil {
		t.Fatal("metered row must cite its interval")
	}

	seats := view.Dimensions[1]
	if seats.Coverage != "DEFERRED" || seats.DeferredReason == "" {
		t.Fatalf("deferred row = %+v", seats)
	}
	if seats.Value != nil || seats.Envelope != nil || seats.WindowStart != nil || seats.State != "" || seats.Trend != "" {
		t.Fatalf("deferred row must carry no number, no state, no trend, no window: %+v", seats)
	}

	egress := view.Dimensions[2]
	if !egress.TelemetryGap || len(egress.Gaps) != 1 || egress.Gaps[0].Reason == "" {
		t.Fatalf("gap row = %+v", egress)
	}
	if egress.Value != nil || egress.WindowStart != nil || egress.Trend != "" {
		t.Fatalf("gap row must carry no usable number and no trend: %+v", egress)
	}

	if len(view.Divergences) != 1 {
		t.Fatalf("divergences = %d, want 1", len(view.Divergences))
	}
	dv := view.Divergences[0]
	if dv.Dimension != "CI_MINUTES" || dv.DataPlaneID != "plane-1" || dv.ControlPlane != 100 || dv.DataPlaneReport != 90 {
		t.Fatalf("divergence = %+v", dv)
	}
	if view.GeneratedAt != end {
		t.Fatalf("generated_at = %v, want %v", view.GeneratedAt, end)
	}
}

// SPEC-0046 AC3: the throttle observation is shaped field for field with its
// metered and applied halves kept separate — absent when the wire carries
// none, the applied half absent until an ack, and a failed ack cited.
func TestGetUsageViewShapesThrottleObservation(t *testing.T) {
	// No observation on the wire: the absent shape stays absent.
	view, err := New(&fakeService{resp: &usagev1.GetUsageViewResponse{}}).GetUsageView(context.Background(), read())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if view.Throttle.Present {
		t.Fatal("no wire observation must yield an absent throttle shape")
	}

	acked := time.Date(2026, 8, 15, 12, 30, 0, 0, time.UTC)
	resp := func(obs *usagev1.EnvelopeThrottleObservation) *usagev1.GetUsageViewResponse {
		return &usagev1.GetUsageViewResponse{EnvelopeThrottle: obs}
	}

	// Metered half only: the applied half stays zero-valued and unacked.
	view, err = New(&fakeService{resp: resp(&usagev1.EnvelopeThrottleObservation{
		DesiredGeneration: 7, DesiredMaxCiConcurrency: 2, DesiredQueueDepthCap: 50,
	})}).GetUsageView(context.Background(), read())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	th := view.Throttle
	if !th.Present || th.DesiredGeneration != 7 || th.DesiredMaxCIConcurrency != 2 || th.DesiredQueueDepthCap != 50 {
		t.Fatalf("metered half = %+v", th)
	}
	if th.HasAppliedAck || th.Applied || th.AckedAt != nil {
		t.Fatalf("the applied half must stay absent until an ack: %+v", th)
	}

	// Applied half with a FAILED ack: the error prose travels untouched.
	view, err = New(&fakeService{resp: resp(&usagev1.EnvelopeThrottleObservation{
		DesiredGeneration: 7, DesiredMaxCiConcurrency: 2, DesiredQueueDepthCap: 50,
		HasAppliedAck: true, AppliedGeneration: 7, Applied: false,
		AppliedError: "scaler unavailable", AckedAt: timestamppb.New(acked),
	})}).GetUsageView(context.Background(), read())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	th = view.Throttle
	if !th.HasAppliedAck || th.AppliedGeneration != 7 || th.Applied || th.AppliedError != "scaler unavailable" {
		t.Fatalf("applied half = %+v", th)
	}
	if th.AckedAt == nil || !th.AckedAt.Equal(acked) {
		t.Fatalf("acked_at = %v, want %v", th.AckedAt, acked)
	}
}

// A backend error is returned as-is: the HTTP surface owns the coarse
// refusal, and no partial view is invented (SPEC-0001).
func TestGetUsageViewPassesBackendErrors(t *testing.T) {
	backend := errors.New("rpc error")
	_, err := New(&fakeService{err: backend}).GetUsageView(context.Background(), read())
	if !errors.Is(err, backend) {
		t.Fatalf("err = %v, want the backend error", err)
	}
}
