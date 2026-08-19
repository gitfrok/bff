// Package reposettings adapts the Repository context's settings surface onto BFF-shaped types
// (T-0069, SPEC-0057, ADR-0076).
//
// It carries verified identity and shapes only. Nothing here carries a visibility, a member, a role,
// a branch protection or an approval requirement: ADR-0076 accepted name, description and archival,
// check-contracts' check 16 keeps the wire free of a field for the rest, so this package has nowhere
// to put one.
package reposettings

import (
	"context"
	"errors"

	repositoryv1 "github.com/gitfrok/bff/gen/proto/repository/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// ErrUnavailable is the one coarse refusal. Whether the repository exists, whether the caller
	// may administer it and whether the backend was reachable are all this error.
	ErrUnavailable = errors.New("repository settings: unavailable")
	// ErrNameRequired is the single distinguished outcome: it is about the field the caller just
	// sent, which the caller already knows, so naming it discloses nothing — and a rename form that
	// fails for no stated reason is a worse product than one that says what was wrong.
	ErrNameRequired = errors.New("repository settings: a name is required")
)

// Settings is one repository's changeable properties.
//
// ArchivedAt is empty when the repository is not archived. The emptiness IS the state: a boolean
// beside it could disagree with it, and this layer has no business deciding which one wins.
type Settings struct {
	RepositoryID      string
	Name              string
	Description       string
	ArchivedAt        string
	SettingsUpdatedAt string
	SettingsUpdatedBy string
}

// Client is the settings port this surface shapes.
type Client struct {
	settings repositoryv1.RepositorySettingsClient
}

// New wires the client onto the generated stub.
func New(settings repositoryv1.RepositorySettingsClient) *Client {
	return &Client{settings: settings}
}

func contextOf(read aggregate.ReadContext) *repositoryv1.ReadContext {
	return &repositoryv1.ReadContext{
		TenantId: read.TenantID, RepositoryId: read.RepositoryID, ActorId: read.ActorID,
		RequestId: read.RequestID, ActorRoles: read.ActorRoles,
	}
}

func view(s *repositoryv1.Settings) Settings {
	return Settings{
		RepositoryID: s.GetRepositoryId(), Name: s.GetName(), Description: s.GetDescription(),
		ArchivedAt:        s.GetArchivedAt(),
		SettingsUpdatedAt: s.GetSettingsUpdatedAt(),
		SettingsUpdatedBy: s.GetSettingsUpdatedBy(),
	}
}

// verified reports whether the session named everything a settings call needs. The actor is never a
// field the browser sends: an actor field would be an unauthenticated authorship claim.
func verified(read aggregate.ReadContext) bool {
	return read.TenantID != "" && read.ActorID != "" && read.RepositoryID != ""
}

// Get reads one repository's settings.
func (c *Client) Get(ctx context.Context, read aggregate.ReadContext) (Settings, error) {
	if !verified(read) {
		return Settings{}, ErrUnavailable
	}
	response, err := c.settings.GetSettings(ctx, &repositoryv1.GetSettingsRequest{Context: contextOf(read)})
	if err != nil {
		return Settings{}, coarse(err)
	}
	return view(response.GetSettings()), nil
}

// Update writes the name and the description.
//
// Both travel on every call, because the contract has no way to say "leave this one alone" — a
// partial-update convention's first attraction is a field that was not in the accepted increment.
func (c *Client) Update(ctx context.Context, read aggregate.ReadContext, name, description string) (Settings, error) {
	if !verified(read) {
		return Settings{}, ErrUnavailable
	}
	if name == "" {
		return Settings{}, ErrNameRequired
	}
	response, err := c.settings.UpdateSettings(ctx, &repositoryv1.UpdateSettingsRequest{
		Context: contextOf(read), Name: name, Description: description,
	})
	if err != nil {
		return Settings{}, coarse(err)
	}
	return view(response.GetSettings()), nil
}

// SetArchived sets or clears the archived label.
//
// It states the state wanted, not the transition, so a caller that repeats itself is accepted and
// changes nothing — the backend decides that, and duplicating the comparison here would be a second
// place idempotency is decided.
func (c *Client) SetArchived(ctx context.Context, read aggregate.ReadContext, archived bool) (Settings, error) {
	if !verified(read) {
		return Settings{}, ErrUnavailable
	}
	response, err := c.settings.SetArchived(ctx, &repositoryv1.SetArchivedRequest{
		Context: contextOf(read), Archived: archived,
	})
	if err != nil {
		return Settings{}, coarse(err)
	}
	return view(response.GetSettings()), nil
}

// coarse collapses every backend failure onto one refusal, keeping the one distinguished outcome the
// backend also distinguishes: an invalid name.
func coarse(err error) error {
	if status.Code(err) == codes.InvalidArgument {
		return ErrNameRequired
	}
	return ErrUnavailable
}
