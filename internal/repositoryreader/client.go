// Package repositoryreader adapts the generated RepositoryReader gRPC client
// onto the BFF aggregation port. It has no policy, storage, or Git logic.
package repositoryreader

import (
	"context"
	"errors"
	"io"
	"slices"

	repositoryv1 "github.com/gitfrok/bff/gen/proto/repository/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

type Client struct {
	reader repositoryv1.RepositoryReaderClient
}

func New(reader repositoryv1.RepositoryReaderClient) *Client { return &Client{reader: reader} }

func (c *Client) Tree(ctx context.Context, read aggregate.ReadContext, revision, pageToken string, pageSize int) (aggregate.TreePage, error) {
	response, err := c.reader.GetTree(ctx, &repositoryv1.GetTreeRequest{Context: contextOf(read), Revision: revision, PageToken: pageToken, PageSize: int32(pageSize)})
	if err != nil {
		return aggregate.TreePage{}, err
	}
	entries := make([]aggregate.TreeEntry, 0, len(response.GetEntries()))
	for _, entry := range response.GetEntries() {
		entries = append(entries, aggregate.TreeEntry{Path: entry.GetPath(), ObjectID: entry.GetObjectId(), Kind: kindOf(entry.GetKind()), Mode: entry.GetMode(), SizeBytes: entry.GetSizeBytes()})
	}
	return aggregate.TreePage{Entries: entries, NextPageToken: response.GetNextPageToken()}, nil
}

func (c *Client) File(ctx context.Context, read aggregate.ReadContext, revision, path string, send func(aggregate.FileChunk) error) error {
	stream, err := c.reader.GetFile(ctx, &repositoryv1.GetFileRequest{Context: contextOf(read), Revision: revision, Path: path})
	if err != nil {
		return err
	}
	for {
		chunk, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			return nil
		}
		if recvErr != nil {
			return recvErr
		}
		mapped := aggregate.FileChunk{Data: slices.Clone(chunk.GetData()), EOF: chunk.GetEof()}
		if metadata := chunk.GetMetadata(); metadata != nil {
			mapped.Metadata = &aggregate.FileMetadata{Path: metadata.GetPath(), ObjectID: metadata.GetObjectId(), Mode: metadata.GetMode(), SizeBytes: metadata.GetSizeBytes()}
		}
		if err := send(mapped); err != nil {
			return err
		}
		if mapped.EOF {
			return nil
		}
	}
}

func (c *Client) Diff(ctx context.Context, read aggregate.ReadContext, baseRevision, headRevision, path string, send func(aggregate.DiffChunk) error) error {
	stream, err := c.reader.GetDiff(ctx, &repositoryv1.GetDiffRequest{Context: contextOf(read), BaseRevision: baseRevision, HeadRevision: headRevision, Path: path})
	if err != nil {
		return err
	}
	for {
		chunk, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			return nil
		}
		if recvErr != nil {
			return recvErr
		}
		mapped := aggregate.DiffChunk{Data: slices.Clone(chunk.GetData()), EOF: chunk.GetEof()}
		if err := send(mapped); err != nil {
			return err
		}
		if mapped.EOF {
			return nil
		}
	}
}

func contextOf(read aggregate.ReadContext) *repositoryv1.ReadContext {
	return &repositoryv1.ReadContext{TenantId: read.TenantID, RepositoryId: read.RepositoryID, ActorId: read.ActorID, RequestId: read.RequestID}
}

func kindOf(kind repositoryv1.EntryKind) aggregate.EntryKind {
	switch kind {
	case repositoryv1.EntryKind_ENTRY_KIND_FILE:
		return aggregate.EntryFile
	case repositoryv1.EntryKind_ENTRY_KIND_DIRECTORY:
		return aggregate.EntryDirectory
	case repositoryv1.EntryKind_ENTRY_KIND_SYMLINK:
		return aggregate.EntrySymlink
	default:
		return aggregate.EntryUnknown
	}
}

var _ aggregate.ReadBackend = (*Client)(nil)
