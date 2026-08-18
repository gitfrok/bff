// Package policyview adapts the policy read surface onto BFF-shaped types (T-0062, SPEC-0055).
//
// Reads only. There is no write here and no place to add one: ADR-0073 records that policy
// authoring is structurally absent — policies live in governance/ and ADR-0001 makes governance the
// Source of Truth — and check-contracts.sh check 14 keeps the contract free of a verb for it.
package policyview

import (
	"context"
	"errors"
	"time"

	policyv1 "github.com/gitfrok/bff/gen/proto/policy/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ErrUnavailable is the one coarse refusal this surface returns.
var ErrUnavailable = errors.New("policy: unavailable")

// BundleStatus is the policy bundle in force.
type BundleStatus struct {
	BundleRevision string
	LoadedAt       string
}

// DecisionRecord is one recorded decision, as a compliance reader consumes it.
type DecisionRecord struct {
	DecisionID     string
	Action         string
	ResourceType   string
	ResourceID     string
	Allowed        bool
	PolicyRevision string
	InputDigest    string
	Mode           string
	DecidedAt      string
}

// Client is the policy read port this surface shapes.
type Client struct {
	pdp policyv1.PolicyDecisionPointClient
}

// New wires the client onto the generated stub.
func New(pdp policyv1.PolicyDecisionPointClient) *Client { return &Client{pdp: pdp} }

// BundleStatus reports which bundle is in force.
func (c *Client) BundleStatus(ctx context.Context, read aggregate.ReadContext) (BundleStatus, error) {
	if read.TenantID == "" || read.ActorID == "" {
		return BundleStatus{}, ErrUnavailable
	}
	response, err := c.pdp.GetBundleStatus(ctx, &policyv1.GetBundleStatusRequest{TenantId: read.TenantID})
	if err != nil {
		return BundleStatus{}, ErrUnavailable
	}
	return BundleStatus{
		BundleRevision: response.GetBundleRevision(),
		LoadedAt:       response.GetLoadedAt(),
	}, nil
}

// Decision reads one recorded decision.
//
// A decision the caller may not read is ABSENT rather than forbidden: the backend answers a
// missing record and a cross-tenant one with the same empty response, and this layer keeps them
// the same by returning the same error for both.
func (c *Client) Decision(ctx context.Context, read aggregate.ReadContext, decisionID string) (DecisionRecord, error) {
	if read.TenantID == "" || read.ActorID == "" || decisionID == "" {
		return DecisionRecord{}, ErrUnavailable
	}
	response, err := c.pdp.GetDecision(ctx, &policyv1.GetDecisionRequest{
		TenantId: read.TenantID, DecisionId: decisionID,
	})
	if err != nil || response.GetRecord() == nil {
		return DecisionRecord{}, ErrUnavailable
	}
	rec := response.GetRecord()
	return DecisionRecord{
		DecisionID:     rec.GetDecisionId(),
		Action:         rec.GetAction(),
		ResourceType:   rec.GetResource().GetType(),
		ResourceID:     rec.GetResource().GetId(),
		Allowed:        rec.GetAllowed(),
		PolicyRevision: rec.GetPolicyRevision(),
		InputDigest:    rec.GetInputDigest(),
		Mode:           rec.GetMode().String(),
		DecidedAt:      stamp(rec.GetDecidedAt()),
	}, nil
}

// stamp renders a protobuf timestamp as RFC3339, or empty when absent — never
// the zero instant, which would put 1970 on a compliance record.
func stamp(ts *timestamppb.Timestamp) string {
	if ts == nil || !ts.IsValid() {
		return ""
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}
