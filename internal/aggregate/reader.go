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
