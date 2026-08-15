// Package usage adapts the generated UsageService gRPC client onto
// BFF-shaped types for the fair-use usage view (SPEC-0041, T-0034). It
// carries verified identity and shapes only: the backend is the metering
// authority and the PDP for usage.view.read (ADR-0061), and nothing here
// computes, adjusts, or authorizes (invariant 18).
package usage

import (
	"context"
	"slices"
	"strings"
	"time"

	agentv1 "github.com/gitfrok/bff/gen/proto/agent/v1"
	usagev1 "github.com/gitfrok/bff/gen/proto/usage/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

// Gap is one telemetry-less interval for a metered dimension (SPEC-0041
// AC3): the data plane was silent here, and absence of events is never
// rendered as absence of usage.
type Gap struct {
	WindowStart time.Time
	WindowEnd   time.Time
	Reason      string
}

// DimensionView is one PRD §6 dimension's row. Every numeric and window
// field is a pointer: nil means the value does not exist — a deferred
// dimension or a telemetry gap has no number to show, never zero (SPEC-0041
// AC2, AC3). The shape deliberately cannot represent "unmeasured" as a
// number.
type DimensionView struct {
	Dimension string
	Coverage  string // "METERED" or "DEFERRED"
	State     string // meaningful only when Coverage is "METERED" and TelemetryGap is false
	// Trend names the direction the backend's counter moved (SPEC-0046
	// AC2), shaped untouched from the wire; the empty string means the row
	// has no number for a trend to describe (deferred or gapped).
	Trend          string
	Value          *float64
	Envelope       *float64
	Notification   *float64
	Unit           string
	WindowStart    *time.Time
	WindowEnd      *time.Time
	TelemetryGap   bool
	Gaps           []Gap
	DeferredReason string
}

// Divergence is one health finding (SPEC-0041 AC1, ADR-0061 §2): both
// numbers travel; the control plane's counter is never adjusted here or
// anywhere downstream.
type Divergence struct {
	Dimension       string
	DataPlaneID     string
	ControlPlane    float64
	DataPlaneReport float64
	WindowStart     time.Time
	WindowEnd       time.Time
}

// ThrottleObservation is SPEC-0046 AC3's end-to-end throttle view as the
// backend returned it: the METERED desired state and the APPLIED ack as two
// separate halves. Present is false until the tenant has an evaluation;
// AckedAt is nil until an ack is recorded — absence travels as absence,
// never as zero or as "applied". Nothing here is computed or smoothed
// (invariant 18).
type ThrottleObservation struct {
	Present                 bool
	DesiredGeneration       int64
	DesiredMaxCIConcurrency int32
	DesiredQueueDepthCap    int64
	HasAppliedAck           bool
	AppliedGeneration       int64
	Applied                 bool
	AppliedError            string
	AckedAt                 *time.Time
}

// View is the tenant's authorized usage view as the backend returned it.
type View struct {
	Dimensions  []DimensionView
	Divergences []Divergence
	Throttle    ThrottleObservation
	GeneratedAt time.Time
}

// Client talks to the backend's UsageService.
type Client struct {
	service usagev1.UsageServiceClient
}

// New wires the adapter onto the generated client.
func New(service usagev1.UsageServiceClient) *Client {
	return &Client{service: service}
}

// GetUsageView returns the caller's authorized usage view. Membership,
// numbers, coverage and gaps come from the backend untouched; an error is
// returned as-is for the HTTP surface to turn into its coarse refusal.
func (c *Client) GetUsageView(ctx context.Context, read aggregate.ReadContext) (View, error) {
	response, err := c.service.GetUsageView(ctx, &usagev1.GetUsageViewRequest{
		Context: &usagev1.UsageContext{
			TenantId:   read.TenantID,
			ActorId:    read.ActorID,
			ActorRoles: slices.Clone(read.ActorRoles),
			RequestId:  read.RequestID,
		},
	})
	if err != nil {
		return View{}, err
	}
	view := View{
		Dimensions:  make([]DimensionView, 0, len(response.GetDimensions())),
		Divergences: make([]Divergence, 0, len(response.GetDivergences())),
	}
	if t := response.GetGeneratedAt(); t != nil {
		view.GeneratedAt = t.AsTime()
	}
	for _, d := range response.GetDimensions() {
		view.Dimensions = append(view.Dimensions, shapeDimension(d))
	}
	for _, dv := range response.GetDivergences() {
		view.Divergences = append(view.Divergences, shapeDivergence(dv))
	}
	// SPEC-0046 AC3: the throttle observation rides only when the backend
	// sent one — a tenant with no evaluation keeps the absent shape.
	if obs := response.GetEnvelopeThrottle(); obs != nil {
		view.Throttle = shapeThrottleObservation(obs)
	}
	return view, nil
}

// shapeDimension maps one wire row onto the browser shape. Numeric fields
// travel only when the backend marks the row METERED without a telemetry
// gap: a deferred or gapped row keeps nil numbers, so a renderer cannot
// show a zero for a value that does not exist (SPEC-0041 AC2, AC3).
func shapeDimension(d *usagev1.UsageDimensionView) DimensionView {
	row := DimensionView{
		Dimension:    dimensionName(d.GetDimension()),
		Coverage:     coverageName(d.GetCoverage()),
		Unit:         d.GetUnit(),
		TelemetryGap: d.GetTelemetryGap(),
		Gaps:         make([]Gap, 0, len(d.GetGaps())),
	}
	for _, g := range d.GetGaps() {
		gap := Gap{Reason: g.GetReason()}
		if t := g.GetWindowStart(); t != nil {
			gap.WindowStart = t.AsTime()
		}
		if t := g.GetWindowEnd(); t != nil {
			gap.WindowEnd = t.AsTime()
		}
		row.Gaps = append(row.Gaps, gap)
	}
	if row.Coverage == "DEFERRED" {
		row.DeferredReason = d.GetDeferredReason()
		return row
	}
	row.State = stateName(d.GetState())
	if !row.TelemetryGap {
		value, envelope, notification := d.GetCurrentValue(), d.GetEnvelopeValue(), d.GetNotificationValue()
		row.Value, row.Envelope, row.Notification = &value, &envelope, &notification
		// SPEC-0046 AC2: the trend travels alongside the number it
		// describes — a gapped row keeps no trend either.
		row.Trend = trendName(d.GetTrend())
		if t := d.GetWindowStart(); t != nil {
			start := t.AsTime()
			row.WindowStart = &start
		}
		if t := d.GetWindowEnd(); t != nil {
			end := t.AsTime()
			row.WindowEnd = &end
		}
	}
	return row
}

func shapeDivergence(dv *usagev1.UsageDivergence) Divergence {
	out := Divergence{
		Dimension:       dimensionName(dv.GetDimension()),
		DataPlaneID:     dv.GetDataPlaneId(),
		ControlPlane:    dv.GetControlPlaneValue(),
		DataPlaneReport: dv.GetDataPlaneReportedValue(),
	}
	if t := dv.GetWindowStart(); t != nil {
		out.WindowStart = t.AsTime()
	}
	if t := dv.GetWindowEnd(); t != nil {
		out.WindowEnd = t.AsTime()
	}
	return out
}

// shapeThrottleObservation maps the wire observation onto the browser
// shape field for field: the metered half always, the applied half only
// once the backend records an ack.
func shapeThrottleObservation(obs *usagev1.EnvelopeThrottleObservation) ThrottleObservation {
	out := ThrottleObservation{
		Present:                 true,
		DesiredGeneration:       obs.GetDesiredGeneration(),
		DesiredMaxCIConcurrency: obs.GetDesiredMaxCiConcurrency(),
		DesiredQueueDepthCap:    obs.GetDesiredQueueDepthCap(),
		HasAppliedAck:           obs.GetHasAppliedAck(),
	}
	if out.HasAppliedAck {
		out.AppliedGeneration = obs.GetAppliedGeneration()
		out.Applied = obs.GetApplied()
		out.AppliedError = obs.GetAppliedError()
		if t := obs.GetAckedAt(); t != nil {
			acked := t.AsTime()
			out.AckedAt = &acked
		}
	}
	return out
}

// dimensionName maps the contract enum onto its short name; an unnamed
// value is the empty string, never an invented one.
func dimensionName(wire agentv1.FairUseDimension) string {
	name := wire.String()
	if strings.HasPrefix(name, "FAIR_USE_DIMENSION_") {
		return strings.TrimPrefix(name, "FAIR_USE_DIMENSION_")
	}
	return ""
}

func coverageName(wire usagev1.DimensionCoverage) string {
	switch wire {
	case usagev1.DimensionCoverage_DIMENSION_COVERAGE_METERED:
		return "METERED"
	case usagev1.DimensionCoverage_DIMENSION_COVERAGE_DEFERRED:
		return "DEFERRED"
	default:
		return ""
	}
}

func stateName(wire agentv1.EnvelopeState) string {
	switch wire {
	case agentv1.EnvelopeState_ENVELOPE_STATE_WITHIN:
		return "WITHIN"
	case agentv1.EnvelopeState_ENVELOPE_STATE_NEAR:
		return "NEAR"
	case agentv1.EnvelopeState_ENVELOPE_STATE_EXCEEDED:
		return "EXCEEDED"
	default:
		return ""
	}
}

// trendName maps the contract trend enum onto its short name; an unnamed
// value is the empty string, never an invented direction.
func trendName(wire usagev1.EnvelopeTrend) string {
	switch wire {
	case usagev1.EnvelopeTrend_ENVELOPE_TREND_FLAT:
		return "FLAT"
	case usagev1.EnvelopeTrend_ENVELOPE_TREND_RISING:
		return "RISING"
	case usagev1.EnvelopeTrend_ENVELOPE_TREND_FALLING:
		return "FALLING"
	default:
		return ""
	}
}
