package aggregate

import "context"

// ReadContext is verified request identity forwarded to RepositoryReader. The
// backend owns authorization; this BFF package only carries the context and
// shapes its result (SPEC-0017 AC5).
type ReadContext struct {
	TenantID, RepositoryID, ActorID, RequestID string
	ActorRoles                                 []string
}

type TreeEntry struct {
	Path, ObjectID string
	Kind           EntryKind
	Mode           uint32
	SizeBytes      int64
}

type EntryKind uint8

const (
	EntryUnknown EntryKind = iota
	EntryFile
	EntryDirectory
	EntrySymlink
)

type TreePage struct {
	Entries       []TreeEntry
	NextPageToken string
}

type FileMetadata struct {
	Path, ObjectID string
	Mode           uint32
	SizeBytes      int64
}

type FileChunk struct {
	Metadata *FileMetadata
	Data     []byte
	EOF      bool
}

type DiffChunk struct {
	Data []byte
	EOF  bool
}

// ReadBackend is the one BFF port for the repository/v1 contract. Its adapter
// is gRPC; keeping contract types outside the aggregate prevents the shaped
// browser surface from growing storage or policy knowledge.
type ReadBackend interface {
	Tree(context.Context, ReadContext, string, string, int) (TreePage, error)
	File(context.Context, ReadContext, string, string, func(FileChunk) error) error
	Diff(context.Context, ReadContext, string, string, string, func(DiffChunk) error) error
	History(context.Context, ReadContext, string, string, string, int32) (HistoryPage, error)
	Blame(context.Context, ReadContext, string, string) (BlameResult, error)
}

// RepositoryReader forwards verified identity and shapes only contract data.
// Deliberately no DecisionPoint: the Repository/Git reader is the PEP for
// `repo.read`, and a BFF-side decision would violate SPEC-0017 AC5.
type RepositoryReader struct{ backend ReadBackend }

func NewRepositoryReader(backend ReadBackend) *RepositoryReader {
	return &RepositoryReader{backend: backend}
}

func (r *RepositoryReader) Tree(ctx context.Context, read ReadContext, revision, pageToken string, pageSize int) (TreePage, error) {
	return r.backend.Tree(ctx, read, revision, pageToken, pageSize)
}

func (r *RepositoryReader) File(ctx context.Context, read ReadContext, revision, path string, send func(FileChunk) error) error {
	return r.backend.File(ctx, read, revision, path, send)
}

func (r *RepositoryReader) Diff(ctx context.Context, read ReadContext, baseRevision, headRevision, path string, send func(DiffChunk) error) error {
	return r.backend.Diff(ctx, read, baseRevision, headRevision, path, send)
}

func (r *RepositoryReader) History(ctx context.Context, read ReadContext, revision, path, pageToken string, pageSize int32) (HistoryPage, error) {
	return r.backend.History(ctx, read, revision, path, pageToken, pageSize)
}

func (r *RepositoryReader) Blame(ctx context.Context, read ReadContext, revision, path string) (BlameResult, error) {
	return r.backend.Blame(ctx, read, revision, path)
}

// --- history and blame shapes (T-0057, SPEC-0053) -------------------------
//
// Every identity field keeps its git_ prefix from the contract to the browser.
// A commit's author is whatever the committer's git config said and git
// verifies none of it; a field called `author` at any layer invites the next
// one to render it as an account, which asserts the platform vouches for a
// name it has never checked. The naming refuses that reading the whole way
// down, which is the same line ADR-0029 draws for an imported declared_actor.

// CommitIdentity is git's word for who authored and committed. It is not, and
// cannot become, a platform principal.
type CommitIdentity struct {
	GitAuthorName     string
	GitAuthorEmail    string
	GitCommitterName  string
	GitCommitterEmail string
	AuthoredAt        string
	CommittedAt       string
}

// Commit is one entry of a ref's history.
type Commit struct {
	CommitID string
	Identity CommitIdentity
	Subject  string
}

// HistoryPage is one page of commits. There is no total: the walk has no end
// anyone counted, so a figure would be invented.
type HistoryPage struct {
	Commits       []Commit
	NextPageToken string
}

// BlameRange is one contiguous run of lines attributed to one commit.
type BlameRange struct {
	StartLine int32
	EndLine   int32
	CommitID  string
	Identity  CommitIdentity
}

// BlameResult carries the ranges and whether the file outran the server's cap.
// Capped travels because a partial attribution must never be renderable as a
// whole one, and no layer above can infer it from a line count.
type BlameResult struct {
	Ranges []BlameRange
	Capped bool
}
