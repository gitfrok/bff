package browser

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gitfrok/bff/internal/aggregate"
)

// stubSession is the authenticated session the middleware would install. The
// tests drive it directly, because what matters here is that the handler takes
// identity from it and from nowhere else.
type stubSession struct {
	read    aggregate.ReadContext
	present bool
}

func (s stubSession) ReadContext(*http.Request) (aggregate.ReadContext, bool) {
	return s.read, s.present
}

func session() stubSession {
	return stubSession{present: true, read: aggregate.ReadContext{
		TenantID: "tenant-a", ActorID: "actor-a", RequestID: "request-a",
	}}
}

// stubReader records what the handler forwarded and replays a scripted result.
type stubReader struct {
	reads      []aggregate.ReadContext
	revisions  []string
	paths      []string
	pageSizes  []int
	tree       aggregate.TreePage
	fileChunks []aggregate.FileChunk
	diffChunks []aggregate.DiffChunk
	err        error
	failAfter  int
}

func (s *stubReader) Tree(_ context.Context, read aggregate.ReadContext, revision, pageToken string, pageSize int) (aggregate.TreePage, error) {
	s.reads = append(s.reads, read)
	s.revisions = append(s.revisions, revision)
	s.pageSizes = append(s.pageSizes, pageSize)
	return s.tree, s.err
}

func (s *stubReader) File(_ context.Context, read aggregate.ReadContext, revision, path string, send func(aggregate.FileChunk) error) error {
	s.reads = append(s.reads, read)
	s.revisions = append(s.revisions, revision)
	s.paths = append(s.paths, path)
	if s.err != nil && s.failAfter == 0 {
		return s.err
	}
	for i, chunk := range s.fileChunks {
		if s.err != nil && i >= s.failAfter {
			return s.err
		}
		if err := send(chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *stubReader) Diff(_ context.Context, read aggregate.ReadContext, base, head, path string, send func(aggregate.DiffChunk) error) error {
	s.reads = append(s.reads, read)
	s.revisions = append(s.revisions, base, head)
	s.paths = append(s.paths, path)
	if s.err != nil {
		return s.err
	}
	for _, chunk := range s.diffChunks {
		if err := send(chunk); err != nil {
			return err
		}
	}
	return nil
}

func serve(t *testing.T, reader Reader, s Session, target string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	New(reader, s).Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder
}

func TestTreeViewShapesTheReadersResult(t *testing.T) {
	reader := &stubReader{tree: aggregate.TreePage{
		Entries: []aggregate.TreeEntry{
			{Path: "README.md", Kind: aggregate.EntryFile, SizeBytes: 12, ObjectID: "object-a"},
			{Path: "src", Kind: aggregate.EntryDirectory},
		},
		NextPageToken: "token-b",
	}}

	response := serve(t, reader, session(), "/v1/repositories/repo-a/tree?revision=main&page_size=50")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"README.md"`) || !strings.Contains(body, "BROWSER_ENTRY_KIND_DIRECTORY") {
		t.Fatalf("body = %s", body)
	}
	if !strings.Contains(body, "token-b") {
		t.Fatalf("continuation token missing: %s", body)
	}
	// Object IDs are storage detail the browser has no use for, and the contract
	// deliberately has no field for one.
	if strings.Contains(body, "object-a") {
		t.Fatalf("the view leaked an object ID: %s", body)
	}
	if got := response.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if reader.pageSizes[0] != 50 {
		t.Fatalf("page size = %d, want the caller's request passed through", reader.pageSizes[0])
	}
}

// The tenant and actor come from the session. A request cannot name either, and
// the repository it names is still checked against that session's identity by the
// backend, not by this layer.
func TestIdentityComesOnlyFromTheSession(t *testing.T) {
	reader := &stubReader{}
	serve(t, reader, session(), "/v1/repositories/repo-a/tree?revision=main&tenant_id=tenant-b&actor_id=root")

	if len(reader.reads) != 1 {
		t.Fatalf("reads = %d", len(reader.reads))
	}
	read := reader.reads[0]
	if read.TenantID != "tenant-a" || read.ActorID != "actor-a" {
		t.Fatalf("read context = %+v, want the session's identity", read)
	}
	if read.RepositoryID != "repo-a" {
		t.Fatalf("repository = %q, want the routed handle", read.RepositoryID)
	}
}

func TestNoSessionMeansNoRead(t *testing.T) {
	reader := &stubReader{}
	for _, target := range []string{
		"/v1/repositories/repo-a/tree?revision=main",
		"/v1/repositories/repo-a/file?revision=main&path=README.md",
		"/v1/repositories/repo-a/diff?base_revision=main&head_revision=topic",
	} {
		response := serve(t, reader, stubSession{}, target)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", target, response.Code)
		}
	}
	if len(reader.reads) != 0 {
		t.Fatalf("an unauthenticated request reached the reader %d times", len(reader.reads))
	}
}

// A path that tries to leave the repository never reaches the reader. The BFF
// passes the value on unchanged, so refusing it here is the only place it can be
// refused before it becomes someone else's input.
func TestAPathThatLeavesTheRepositoryIsRefused(t *testing.T) {
	reader := &stubReader{fileChunks: []aggregate.FileChunk{{Data: []byte("x")}}}

	for _, path := range []string{
		"/etc/passwd", "../secrets", "src/../../etc/passwd", "%2e%2e/secrets",
		"src//nested", "back%5Cslash", "with%00nul", "",
	} {
		response := serve(t, reader, session(), "/v1/repositories/repo-a/file?revision=main&path="+path)
		if response.Code != http.StatusNotFound {
			t.Errorf("path %q: status = %d, want 404", path, response.Code)
		}
	}
	if len(reader.reads) != 0 {
		t.Fatalf("a refused path reached the reader %d times", len(reader.reads))
	}
}

// Decoding happens exactly once: a path that is safe after one decode must not be
// decoded again into one that is not.
func TestAPathIsDecodedExactlyOnce(t *testing.T) {
	reader := &stubReader{fileChunks: []aggregate.FileChunk{{Data: []byte("x")}}}
	// %252e is "%2e" after one decode — a second decode would make it "..".
	serve(t, reader, session(), "/v1/repositories/repo-a/file?revision=main&path=docs/%252e%252e/readme")

	if len(reader.paths) != 1 {
		t.Fatalf("paths forwarded = %v", reader.paths)
	}
	if strings.Contains(reader.paths[0], "..") {
		t.Fatalf("path %q was decoded twice", reader.paths[0])
	}
}

func TestARevisionGitWouldReinterpretIsRefused(t *testing.T) {
	reader := &stubReader{}
	for _, revision := range []string{"", "--upload-pack=evil", "main..topic", "main%5E", "a%20b", "main%3Apath"} {
		response := serve(t, reader, session(), "/v1/repositories/repo-a/tree?revision="+revision)
		if response.Code != http.StatusNotFound {
			t.Errorf("revision %q: status = %d, want 404", revision, response.Code)
		}
	}
	if len(reader.reads) != 0 {
		t.Fatalf("a refused revision reached the reader %d times", len(reader.reads))
	}
}

func TestFileViewSendsMetadataOnceThenBytes(t *testing.T) {
	reader := &stubReader{fileChunks: []aggregate.FileChunk{
		{Metadata: &aggregate.FileMetadata{Path: "README.md", SizeBytes: 5, ObjectID: "object-a"}, Data: []byte("hello")},
		{Data: []byte(" world"), EOF: true},
	}}

	response := serve(t, reader, session(), "/v1/repositories/repo-a/file?revision=main&path=README.md")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if response.Body.String() != "hello world" {
		t.Fatalf("body = %q", response.Body.String())
	}
	metadata := response.Header().Get(fileMetadataHeader)
	if !strings.Contains(metadata, "README.md") || !strings.Contains(metadata, "main") {
		t.Fatalf("metadata = %q", metadata)
	}
	if strings.Contains(metadata, "object-a") {
		t.Fatalf("metadata leaked an object ID: %q", metadata)
	}
	if got := response.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

// A read that fails before its first byte must leave no body and no metadata —
// otherwise a failed read is indistinguishable from an empty file.
func TestAFailedReadEmitsNoPartialBody(t *testing.T) {
	reader := &stubReader{err: errors.New("reader unavailable")}

	response := serve(t, reader, session(), "/v1/repositories/repo-a/file?revision=main&path=README.md")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if response.Header().Get(fileMetadataHeader) != "" {
		t.Fatal("a failed read still sent file metadata")
	}
	if body := response.Body.String(); strings.Contains(body, "hello") {
		t.Fatalf("a failed read sent a partial body: %q", body)
	}
}

func TestDiffViewStreamsAndFiltersByPath(t *testing.T) {
	reader := &stubReader{diffChunks: []aggregate.DiffChunk{
		{Data: []byte("--- a/README.md\n")}, {Data: []byte("+++ b/README.md\n"), EOF: true},
	}}

	response := serve(t, reader, session(), "/v1/repositories/repo-a/diff?base_revision=main&head_revision=topic&path=README.md")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if !strings.HasPrefix(response.Body.String(), "--- a/README.md") {
		t.Fatalf("body = %q", response.Body.String())
	}
	if reader.paths[0] != "README.md" {
		t.Fatalf("path filter = %q", reader.paths[0])
	}
	if got := response.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

// A diff without a path filter is the whole diff, which is a legitimate request.
func TestDiffViewWithoutAPathFilterIsAllowed(t *testing.T) {
	reader := &stubReader{diffChunks: []aggregate.DiffChunk{{Data: []byte("diff"), EOF: true}}}
	response := serve(t, reader, session(), "/v1/repositories/repo-a/diff?base_revision=main&head_revision=topic")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if reader.paths[0] != "" {
		t.Fatalf("path filter = %q, want none", reader.paths[0])
	}
}

func TestAnUnusableRepositoryHandleIsRefused(t *testing.T) {
	reader := &stubReader{}
	for _, handle := range []string{"-flag", "repo%2F..%2Fother", "repo%20a", strings.Repeat("r", 200)} {
		response := serve(t, reader, session(), "/v1/repositories/"+handle+"/tree?revision=main")
		if response.Code == http.StatusOK {
			t.Errorf("handle %q was accepted", handle)
		}
	}
	if len(reader.reads) != 0 {
		t.Fatalf("a refused handle reached the reader %d times", len(reader.reads))
	}
}

// Every refusal about a repository is the same one. A browser-facing error that
// distinguished "no such revision" from "another tenant's repository" would
// enumerate both.
func TestEveryRepositoryRefusalLooksTheSame(t *testing.T) {
	bodies := map[string]struct{}{}
	for _, target := range []string{
		"/v1/repositories/repo-a/tree?revision=main..topic",
		"/v1/repositories/repo-a/file?revision=main&path=../escape",
		"/v1/repositories/repo-a/diff?base_revision=main&head_revision=",
	} {
		response := serve(t, &stubReader{err: errors.New("unavailable")}, session(), target)
		bodies[strings.TrimSpace(response.Body.String())] = struct{}{}
	}
	if len(bodies) != 1 {
		t.Fatalf("refusals differ between causes: %v", bodies)
	}
}
