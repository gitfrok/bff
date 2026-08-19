// Package releases adapts the Release context and the tag list onto BFF-shaped types
// (T-0065, SPEC-0056).
//
// It carries verified identity and shapes only. Nothing here carries an artifact: ADR-0075 accepted
// the tags-and-notes increment, and check-contracts.sh check 15 keeps the wire free of a field for
// one, so this package would have nowhere to put it.
package releases

import (
	"context"
	"errors"

	releasev1 "github.com/gitfrok/bff/gen/proto/release/v1"
	repositoryv1 "github.com/gitfrok/bff/gen/proto/repository/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// ErrUnavailable is the one coarse refusal.
	ErrUnavailable = errors.New("releases: unavailable")
	// ErrAlreadyPublished is the single distinguished outcome: it reports a conflict with a state
	// the caller can already see, which is not a disclosure.
	ErrAlreadyPublished = errors.New("releases: this tag already has a release")
)

// Tag is a tag and the commit it points at RIGHT NOW.
type Tag struct {
	Name     string
	CommitID string
}

// Release is the record. PublishedCommit is what the tag pointed at when it was published — not
// what it points at now, which is the whole reason both exist.
type Release struct {
	Tag             string
	PublishedCommit string
	Notes           string
	PublishedBy     string
	PublishedAt     string
	NotesUpdatedAt  string
}

// Client is the release port this surface shapes.
type Client struct {
	releases releasev1.ReleaseServiceClient
	reader   repositoryv1.RepositoryReaderClient
}

// New wires the client onto the generated stubs.
func New(releases releasev1.ReleaseServiceClient, reader repositoryv1.RepositoryReaderClient) *Client {
	return &Client{releases: releases, reader: reader}
}

func contextOf(read aggregate.ReadContext) *releasev1.ReleaseContext {
	return &releasev1.ReleaseContext{
		TenantId: read.TenantID, RepositoryId: read.RepositoryID, ActorId: read.ActorID,
		RequestId: read.RequestID, ActorRoles: read.ActorRoles,
	}
}

func view(r *releasev1.Release) Release {
	return Release{
		Tag: r.GetTag(), PublishedCommit: r.GetPublishedCommit(), Notes: r.GetNotes(),
		PublishedBy: r.GetPublishedBy(), PublishedAt: r.GetPublishedAt(),
		NotesUpdatedAt: r.GetNotesUpdatedAt(),
	}
}

// Tags lists a repository's tags with what each points at now.
func (c *Client) Tags(ctx context.Context, read aggregate.ReadContext, pageToken string, pageSize int32) ([]Tag, string, error) {
	if read.TenantID == "" || read.ActorID == "" || read.RepositoryID == "" {
		return nil, "", ErrUnavailable
	}
	response, err := c.reader.ListTags(ctx, &repositoryv1.ListTagsRequest{
		Context: &repositoryv1.ReadContext{
			TenantId: read.TenantID, RepositoryId: read.RepositoryID, ActorId: read.ActorID,
			RequestId: read.RequestID, ActorRoles: read.ActorRoles,
		},
		PageToken: pageToken, PageSize: pageSize,
	})
	if err != nil {
		return nil, "", ErrUnavailable
	}
	tags := make([]Tag, 0, len(response.GetTags()))
	for _, t := range response.GetTags() {
		tags = append(tags, Tag{Name: t.GetName(), CommitID: t.GetCommitId()})
	}
	return tags, response.GetNextPageToken(), nil
}

// Publish announces a release against a tag.
func (c *Client) Publish(ctx context.Context, read aggregate.ReadContext, tag, notes string) (Release, error) {
	if read.TenantID == "" || read.ActorID == "" || read.RepositoryID == "" || tag == "" {
		return Release{}, ErrUnavailable
	}
	response, err := c.releases.PublishRelease(ctx, &releasev1.PublishReleaseRequest{
		Context: contextOf(read), Tag: tag, Notes: notes,
	})
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return Release{}, ErrAlreadyPublished
		}
		return Release{}, ErrUnavailable
	}
	return view(response.GetRelease()), nil
}

// Get reads one release exactly as recorded.
func (c *Client) Get(ctx context.Context, read aggregate.ReadContext, tag string) (Release, error) {
	if read.TenantID == "" || read.ActorID == "" || tag == "" {
		return Release{}, ErrUnavailable
	}
	response, err := c.releases.GetRelease(ctx, &releasev1.GetReleaseRequest{Context: contextOf(read), Tag: tag})
	if err != nil {
		return Release{}, ErrUnavailable
	}
	return view(response.GetRelease()), nil
}

// List pages a repository's releases.
func (c *Client) List(ctx context.Context, read aggregate.ReadContext, pageToken string, pageSize int32) ([]Release, string, error) {
	if read.TenantID == "" || read.ActorID == "" {
		return nil, "", ErrUnavailable
	}
	response, err := c.releases.ListReleases(ctx, &releasev1.ListReleasesRequest{
		Context: contextOf(read), PageToken: pageToken, PageSize: pageSize,
	})
	if err != nil {
		return nil, "", ErrUnavailable
	}
	out := make([]Release, 0, len(response.GetReleases()))
	for _, r := range response.GetReleases() {
		out = append(out, view(r))
	}
	return out, response.GetNextPageToken(), nil
}

// UpdateNotes corrects the prose. There is no method here that moves a release.
func (c *Client) UpdateNotes(ctx context.Context, read aggregate.ReadContext, tag, notes string) (Release, error) {
	if read.TenantID == "" || read.ActorID == "" || tag == "" {
		return Release{}, ErrUnavailable
	}
	response, err := c.releases.UpdateReleaseNotes(ctx, &releasev1.UpdateReleaseNotesRequest{
		Context: contextOf(read), Tag: tag, Notes: notes,
	})
	if err != nil {
		return Release{}, ErrUnavailable
	}
	return view(response.GetRelease()), nil
}
