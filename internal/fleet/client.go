// Package fleet adapts the Agent context's FleetReader onto BFF-shaped types for
// the admin area (T-0072, SPEC-0058, ADR-0077).
//
// It carries verified identity and shapes only. Nothing here reinterprets a
// status: a stale plane arrives stale and leaves stale, because the control plane
// is the only thing that knows when it last heard from a plane and this layer is
// not going to guess on its behalf.
//
// There is no audit read in this package and no route that could grow one. The
// audit log is reached through a scoped, time-boxed, revocable grant (SPEC-0033),
// and check-contracts' check 17 keeps the wire free of a field for one, so this
// package has nowhere to put it.
package fleet

import (
	"context"
	"errors"

	agentv1 "github.com/gitfrok/bff/gen/proto/agent/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

// ErrUnavailable is the one coarse refusal. It also covers the door not being
// configured at all — which is the important case: an unreachable fleet door and a
// tenant with no data planes are different facts, and reporting the first as the
// second would tell an administrator their fleet is empty when it is not.
var ErrUnavailable = errors.New("fleet: unavailable")

// Plane is what the control plane last heard from one data plane.
//
// LastSeenAt is empty for a plane that has never connected. The emptiness is the
// state: a consumer computing an age has nothing to compute, which is exactly
// right — there has been no contact to measure from.
type Plane struct {
	DataPlaneID          string
	Status               string
	Cloud                string
	Region               string
	AgentVersion         string
	K8sVersion           string
	LastSeenAt           string
	EnrolledAt           string
	CertificateExpiresAt string
	// TokenID is set for a provisioned-but-never-connected row: an enrolment token
	// that has not been spent. It is a data plane somebody meant to have.
	TokenID string
}

// Client is the fleet port this surface shapes.
type Client struct {
	fleet agentv1.FleetReaderClient
}

// New wires the client onto the generated stub. A nil stub is the unconfigured
// door, and every call refuses — see ErrUnavailable.
func New(fleet agentv1.FleetReaderClient) *Client { return &Client{fleet: fleet} }

// List returns one tenant's data planes as the control plane last heard them.
func (c *Client) List(ctx context.Context, read aggregate.ReadContext) ([]Plane, error) {
	if c == nil || c.fleet == nil {
		return nil, ErrUnavailable
	}
	if read.TenantID == "" || read.ActorID == "" {
		return nil, ErrUnavailable
	}
	response, err := c.fleet.ListFleet(ctx, &agentv1.ListFleetRequest{
		Context: &agentv1.FleetContext{
			TenantId: read.TenantID, ActorId: read.ActorID,
			ActorRoles: read.ActorRoles, RequestId: read.RequestID,
		},
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	planes := make([]Plane, 0, len(response.GetPlanes()))
	for _, p := range response.GetPlanes() {
		planes = append(planes, Plane{
			DataPlaneID:          p.GetDataPlaneId(),
			Status:               p.GetStatus(),
			Cloud:                p.GetCloud(),
			Region:               p.GetRegion(),
			AgentVersion:         p.GetAgentVersion(),
			K8sVersion:           p.GetK8SVersion(),
			LastSeenAt:           p.GetLastSeenAt(),
			EnrolledAt:           p.GetEnrolledAt(),
			CertificateExpiresAt: p.GetCertificateExpiresAt(),
			TokenID:              p.GetTokenId(),
		})
	}
	return planes, nil
}
