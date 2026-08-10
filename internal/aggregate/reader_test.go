package aggregate

import (
	"context"
	"reflect"
	"testing"
)

type stubReadBackend struct {
	treeRequest ReadContext
	fileRequest ReadContext
	diffRequest ReadContext
}

func (s *stubReadBackend) Tree(_ context.Context, read ReadContext, revision, token string, pageSize int) (TreePage, error) {
	s.treeRequest = read
	return TreePage{Entries: []TreeEntry{{Path: "README.md", ObjectID: "abc", SizeBytes: 7}}, NextPageToken: "next"}, nil
}
func (s *stubReadBackend) File(_ context.Context, read ReadContext, revision, path string, send func(FileChunk) error) error {
	s.fileRequest = read
	return send(FileChunk{Metadata: &FileMetadata{Path: path, ObjectID: "abc", SizeBytes: 7}, Data: []byte("content"), EOF: true})
}
func (s *stubReadBackend) Diff(_ context.Context, read ReadContext, base, head, path string, send func(DiffChunk) error) error {
	s.diffRequest = read
	return send(DiffChunk{Data: []byte("patch"), EOF: true})
}

// SPEC-0017 AC5: this layer only shapes RepositoryReader results. It has no
// PDP, storage, Git parsing, or authorization result to derive.
func TestRepositoryReaderShapesOnlyBackendResults(t *testing.T) {
	backend := &stubReadBackend{}
	reader := NewRepositoryReader(backend)
	ctx := context.Background()
	read := ReadContext{TenantID: "tenant-a", RepositoryID: "repo-a", ActorID: "actor-a", RequestID: "request-a"}

	tree, err := reader.Tree(ctx, read, "main", "", 100)
	if err != nil || len(tree.Entries) != 1 || tree.Entries[0].Path != "README.md" || tree.NextPageToken != "next" {
		t.Fatalf("tree=%+v err=%v", tree, err)
	}
	if !reflect.DeepEqual(backend.treeRequest, read) {
		t.Fatalf("tree context=%+v want=%+v", backend.treeRequest, read)
	}
	var file []byte
	if err := reader.File(ctx, read, "main", "README.md", func(chunk FileChunk) error { file = append(file, chunk.Data...); return nil }); err != nil {
		t.Fatal(err)
	}
	if string(file) != "content" || !reflect.DeepEqual(backend.fileRequest, read) {
		t.Fatalf("file=%q context=%+v", file, backend.fileRequest)
	}
	var diff []byte
	if err := reader.Diff(ctx, read, "base", "head", "", func(chunk DiffChunk) error { diff = append(diff, chunk.Data...); return nil }); err != nil {
		t.Fatal(err)
	}
	if string(diff) != "patch" || !reflect.DeepEqual(backend.diffRequest, read) {
		t.Fatalf("diff=%q context=%+v", diff, backend.diffRequest)
	}
}
