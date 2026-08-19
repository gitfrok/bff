package reposettings_test

import (
	"context"
	"errors"
	"testing"

	repositoryv1 "github.com/gitfrok/bff/gen/proto/repository/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/reposettings"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SPEC-0057 AC13: the client carries the verified context and shapes only, and every backend failure
// collapses onto one refusal except the invalid name.

type stubSettings struct {
	repositoryv1.RepositorySettingsClient
	settings *repositoryv1.Settings
	err      error
	gotCtx   *repositoryv1.ReadContext
	gotName  string
	gotDesc  string
	gotArch  bool
}

func (s *stubSettings) GetSettings(_ context.Context, in *repositoryv1.GetSettingsRequest, _ ...grpc.CallOption) (*repositoryv1.GetSettingsResponse, error) {
	s.gotCtx = in.GetContext()
	if s.err != nil {
		return nil, s.err
	}
	return &repositoryv1.GetSettingsResponse{Settings: s.settings}, nil
}

func (s *stubSettings) UpdateSettings(_ context.Context, in *repositoryv1.UpdateSettingsRequest, _ ...grpc.CallOption) (*repositoryv1.UpdateSettingsResponse, error) {
	s.gotCtx, s.gotName, s.gotDesc = in.GetContext(), in.GetName(), in.GetDescription()
	if s.err != nil {
		return nil, s.err
	}
	return &repositoryv1.UpdateSettingsResponse{Settings: s.settings}, nil
}

func (s *stubSettings) SetArchived(_ context.Context, in *repositoryv1.SetArchivedRequest, _ ...grpc.CallOption) (*repositoryv1.SetArchivedResponse, error) {
	s.gotCtx, s.gotArch = in.GetContext(), in.GetArchived()
	if s.err != nil {
		return nil, s.err
	}
	return &repositoryv1.SetArchivedResponse{Settings: s.settings}, nil
}

func read() aggregate.ReadContext {
	return aggregate.ReadContext{
		TenantID: "t-1", RepositoryID: "repo-1", ActorID: "owner@x",
		RequestID: "req-1", ActorRoles: []string{"owner"},
	}
}

func TestGetCarriesTheVerifiedContext(t *testing.T) {
	stub := &stubSettings{settings: &repositoryv1.Settings{
		RepositoryId: "repo-1", Name: "infra", Description: "the cluster",
	}}
	got, err := reposettings.New(stub).Get(context.Background(), read())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stub.gotCtx.GetTenantId() != "t-1" || stub.gotCtx.GetActorId() != "owner@x" || stub.gotCtx.GetRepositoryId() != "repo-1" {
		t.Errorf("context not forwarded: %+v", stub.gotCtx)
	}
	if got.Name != "infra" || got.Description != "the cluster" {
		t.Errorf("unexpected settings %+v", got)
	}
}

func TestUpdateSendsBothFieldsEveryTime(t *testing.T) {
	stub := &stubSettings{settings: &repositoryv1.Settings{RepositoryId: "repo-1", Name: "platform"}}
	if _, err := reposettings.New(stub).Update(context.Background(), read(), "platform", ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if stub.gotName != "platform" {
		t.Errorf("name not forwarded: %q", stub.gotName)
	}
	// An empty description is a cleared description, not an absent field. There is no way to say
	// "leave it alone", by design: a partial-update convention's first attraction is a field that
	// was not in the accepted increment.
	if stub.gotDesc != "" {
		t.Errorf("description not forwarded as cleared: %q", stub.gotDesc)
	}
}

func TestAnEmptyNameNeverReachesTheBackend(t *testing.T) {
	stub := &stubSettings{}
	if _, err := reposettings.New(stub).Update(context.Background(), read(), "", "prose"); !errors.Is(err, reposettings.ErrNameRequired) {
		t.Fatalf("want ErrNameRequired, got %v", err)
	}
	if stub.gotCtx != nil {
		t.Error("the backend was called with a nameless update")
	}
}

func TestAnIncompleteSessionNeverReachesTheBackend(t *testing.T) {
	for name, rc := range map[string]aggregate.ReadContext{
		"no tenant":     {RepositoryID: "repo-1", ActorID: "owner@x"},
		"no actor":      {TenantID: "t-1", RepositoryID: "repo-1"},
		"no repository": {TenantID: "t-1", ActorID: "owner@x"},
	} {
		stub := &stubSettings{}
		if _, err := reposettings.New(stub).SetArchived(context.Background(), rc, true); !errors.Is(err, reposettings.ErrUnavailable) {
			t.Errorf("%s: want ErrUnavailable, got %v", name, err)
		}
		if stub.gotCtx != nil {
			t.Errorf("%s: the backend was called", name)
		}
	}
}

func TestEveryBackendFailureIsCoarseExceptTheInvalidName(t *testing.T) {
	cases := map[string]struct {
		err  error
		want error
	}{
		"permission denied": {status.Error(codes.PermissionDenied, "repository: unavailable"), reposettings.ErrUnavailable},
		"unavailable":       {status.Error(codes.Unavailable, "no backend"), reposettings.ErrUnavailable},
		"not found":         {status.Error(codes.NotFound, "gone"), reposettings.ErrUnavailable},
		"invalid argument":  {status.Error(codes.InvalidArgument, "repository: a name is required"), reposettings.ErrNameRequired},
	}
	for name, c := range cases {
		_, err := reposettings.New(&stubSettings{err: c.err}).Get(context.Background(), read())
		if !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
}

// The archived state travels as asked. Whether it changed anything is the backend's answer, and
// comparing here would be a second place idempotency is decided.
func TestSetArchivedForwardsTheStateWanted(t *testing.T) {
	stub := &stubSettings{settings: &repositoryv1.Settings{RepositoryId: "repo-1", Name: "infra"}}
	if _, err := reposettings.New(stub).SetArchived(context.Background(), read(), false); err != nil {
		t.Fatalf("SetArchived: %v", err)
	}
	if stub.gotArch {
		t.Error("the state wanted was not forwarded")
	}
}
