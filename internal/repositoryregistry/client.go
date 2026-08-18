// Package repositoryregistry adapts the RepositoryRegistry gRPC client onto BFF-shaped types
// (T-0054, SPEC-0052).
//
// It carries verified identity and shapes only (invariant 18). The listable set is derived by the
// backend from the caller's authorization at request time; nothing here filters, ranks or
// authorizes, and the request has no field with which a caller could try to.
package repositoryregistry

import (
	"context"
	"errors"

	repositoryv1 "github.com/gitfrok/bff/gen/proto/repository/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

// ErrUnavailable is the one coarse refusal this surface returns. It distinguishes nothing about
// what exists or what is allowed.
var ErrUnavailable = errors.New("repository registry: unavailable")

// Summary is one repository as the caller observes it: an opaque identifier and a name, and no
// permission fact.
type Summary struct {
	RepositoryID string
	Name         string
}

// Page is one page of the caller's repositories.
//
// It has no total, and the absence is carried deliberately from the contract: no field is capable
// of expressing how many repositories the caller may not see, so non-enumeration survives every
// layer rather than being re-decided at each one (SPEC-0052 AC5).
type Page struct {
	Repositories  []Summary
	NextPageToken string
}

// Client is the registry port this surface shapes.
type Client struct {
	registry repositoryv1.RepositoryRegistryClient
}

// New wires the client onto the generated stub.
func New(registry repositoryv1.RepositoryRegistryClient) *Client {
	return &Client{registry: registry}
}

// List asks which repositories the caller may see.
//
// The read context's RepositoryID is deliberately ignored: a list has no repository to name, and
// ListContext has no field to put one in. That is what keeps a caller from asking about a
// repository by listing.
func (c *Client) List(ctx context.Context, read aggregate.ReadContext, pageToken string, pageSize int32) (Page, error) {
	if read.TenantID == "" || read.ActorID == "" {
		return Page{}, ErrUnavailable
	}
	response, err := c.registry.ListRepositories(ctx, &repositoryv1.ListRepositoriesRequest{
		Context: &repositoryv1.ListContext{
			TenantId:   read.TenantID,
			ActorId:    read.ActorID,
			RequestId:  read.RequestID,
			ActorRoles: read.ActorRoles,
		},
		PageToken: pageToken,
		PageSize:  pageSize,
	})
	if err != nil {
		return Page{}, ErrUnavailable
	}
	page := Page{
		Repositories:  make([]Summary, 0, len(response.GetRepositories())),
		NextPageToken: response.GetNextPageToken(),
	}
	for _, r := range response.GetRepositories() {
		page.Repositories = append(page.Repositories, Summary{RepositoryID: r.GetRepositoryId(), Name: r.GetName()})
	}
	return page, nil
}
