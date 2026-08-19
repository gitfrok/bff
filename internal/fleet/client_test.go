package fleet_test

import (
	"context"
	"errors"
	"testing"

	agentv1 "github.com/gitfrok/bff/gen/proto/agent/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/fleet"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SPEC-0058 AC9/AC10: the client carries the verified caller, shapes what came
// back, and treats an unconfigured door as unavailable rather than as an empty
// fleet.

type stubFleet struct {
	agentv1.FleetReaderClient
	planes []*agentv1.DataPlaneReport
	err    error
	gotCtx *agentv1.FleetContext
}

func (s *stubFleet) ListFleet(_ context.Context, in *agentv1.ListFleetRequest, _ ...grpc.CallOption) (*agentv1.ListFleetResponse, error) {
	s.gotCtx = in.GetContext()
	if s.err != nil {
		return nil, s.err
	}
	return &agentv1.ListFleetResponse{Planes: s.planes}, nil
}

func read() aggregate.ReadContext {
	return aggregate.ReadContext{
		TenantID: "t-1", ActorID: "owner@x", ActorRoles: []string{"owner"}, RequestID: "req-1",
	}
}

func TestListCarriesTheVerifiedCaller(t *testing.T) {
	stub := &stubFleet{planes: []*agentv1.DataPlaneReport{{
		DataPlaneId: "dp-1", Status: "CONNECTED", Region: "eu-west-1",
		K8SVersion: "1.30", LastSeenAt: "2026-08-19T09:00:00Z",
	}}}

	got, err := fleet.New(stub).List(context.Background(), read())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if stub.gotCtx.GetTenantId() != "t-1" || stub.gotCtx.GetActorId() != "owner@x" {
		t.Errorf("context not forwarded: %+v", stub.gotCtx)
	}
	if len(got) != 1 || got[0].DataPlaneID != "dp-1" || got[0].K8sVersion != "1.30" {
		t.Fatalf("unexpected planes %+v", got)
	}
	if got[0].LastSeenAt != "2026-08-19T09:00:00Z" {
		t.Errorf("the age must survive shaping: %q", got[0].LastSeenAt)
	}
}

// AC10: the unconfigured door. A nil stub is a deployment that was never given the
// address, and it must not look like a tenant with no data planes.
func TestAnUnconfiguredDoorRefuses(t *testing.T) {
	if _, err := fleet.New(nil).List(context.Background(), read()); !errors.Is(err, fleet.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestAnIncompleteSessionNeverReachesTheDoor(t *testing.T) {
	for name, rc := range map[string]aggregate.ReadContext{
		"no tenant": {ActorID: "owner@x"},
		"no actor":  {TenantID: "t-1"},
	} {
		stub := &stubFleet{}
		if _, err := fleet.New(stub).List(context.Background(), rc); !errors.Is(err, fleet.ErrUnavailable) {
			t.Errorf("%s: want ErrUnavailable, got %v", name, err)
		}
		if stub.gotCtx != nil {
			t.Errorf("%s: the door was called", name)
		}
	}
}

func TestEveryBackendFailureIsTheSameRefusal(t *testing.T) {
	for name, err := range map[string]error{
		"permission denied": status.Error(codes.PermissionDenied, "agent: fleet unavailable"),
		"unimplemented":     status.Error(codes.Unimplemented, "no such service"),
		"unavailable":       status.Error(codes.Unavailable, "no backend"),
	} {
		if _, got := fleet.New(&stubFleet{err: err}).List(context.Background(), read()); !errors.Is(got, fleet.ErrUnavailable) {
			t.Errorf("%s: want ErrUnavailable, got %v", name, got)
		}
	}
}

// An empty fleet is a successful answer with no planes — never an error, because
// "you may see none" and "there are none" must stay indistinguishable.
func TestAnEmptyFleetIsNotAnError(t *testing.T) {
	got, err := fleet.New(&stubFleet{}).List(context.Background(), read())
	if err != nil {
		t.Fatalf("an empty fleet must not be an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no planes, got %d", len(got))
	}
}
