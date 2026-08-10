package repositoryreader

import (
	"context"
	"net"
	"testing"

	repositoryv1 "github.com/gitfrok/bff/gen/proto/repository/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type readerServer struct {
	repositoryv1.UnimplementedRepositoryReaderServer
	tree *repositoryv1.GetTreeRequest
}

func (s *readerServer) GetTree(_ context.Context, req *repositoryv1.GetTreeRequest) (*repositoryv1.GetTreeResponse, error) {
	s.tree = req
	return &repositoryv1.GetTreeResponse{Entries: []*repositoryv1.TreeEntry{{Path: "README.md", Kind: repositoryv1.EntryKind_ENTRY_KIND_FILE, ObjectId: "abc", Mode: 0o100644, SizeBytes: 7}}, NextPageToken: "opaque"}, nil
}
func (s *readerServer) GetFile(_ *repositoryv1.GetFileRequest, stream repositoryv1.RepositoryReader_GetFileServer) error {
	return stream.Send(&repositoryv1.FileChunk{Metadata: &repositoryv1.FileMetadata{Path: "README.md", ObjectId: "abc", Mode: 0o100644, SizeBytes: 7}, Data: []byte("content"), Eof: true})
}
func (s *readerServer) GetDiff(_ *repositoryv1.GetDiffRequest, stream repositoryv1.RepositoryReader_GetDiffServer) error {
	return stream.Send(&repositoryv1.DiffChunk{Data: []byte("patch"), Eof: true})
}

func TestClientMapsRepositoryReaderWithoutDerivation(t *testing.T) {
	server := &readerServer{}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	repositoryv1.RegisterRepositoryReaderServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() { grpcServer.Stop(); _ = listener.Close() })
	conn, err := grpc.NewClient("passthrough:///repository-reader", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := New(repositoryv1.NewRepositoryReaderClient(conn))
	read := aggregate.ReadContext{TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "request-a"}

	tree, err := client.Tree(t.Context(), read, "main", "", 100)
	if err != nil || len(tree.Entries) != 1 || tree.Entries[0].Kind != aggregate.EntryFile || tree.NextPageToken != "opaque" {
		t.Fatalf("tree=%+v err=%v", tree, err)
	}
	if got := server.tree.GetContext(); got.GetTenantId() != read.TenantID || got.GetRepositoryId() != read.RepositoryID || got.GetActorId() != read.ActorID || got.GetRequestId() != read.RequestID {
		t.Fatalf("context=%+v want=%+v", got, read)
	}
	var file []byte
	if err := client.File(t.Context(), read, "main", "README.md", func(chunk aggregate.FileChunk) error { file = append(file, chunk.Data...); return nil }); err != nil {
		t.Fatal(err)
	}
	if string(file) != "content" {
		t.Fatalf("file=%q", file)
	}
	var diff []byte
	if err := client.Diff(t.Context(), read, "base", "head", "", func(chunk aggregate.DiffChunk) error { diff = append(diff, chunk.Data...); return nil }); err != nil {
		t.Fatal(err)
	}
	if string(diff) != "patch" {
		t.Fatalf("diff=%q", diff)
	}
}
