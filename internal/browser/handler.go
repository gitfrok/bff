// Package browser serves the BFF's tree, file and diff views to the web
// frontend (SPEC-0021).
//
// It shapes and forwards; it decides nothing. Repository/Git is the `repo.read`
// enforcement point, so there is no PDP here — a second decision at this layer
// would be a second answer to a question that already has one (SPEC-0017 AC5).
//
// The identity a request runs under comes only from the authenticated session.
// Nothing in a URL, a query string or a header can name a tenant, an actor, a
// role, or an outcome: this is the layer closest to an untrusted caller, so it is
// the worst possible place to accept any of them.
package browser

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"context"

	bffv1 "github.com/gitfrok/bff/gen/proto/bff/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/protobuf/encoding/protojson"
)

// Session resolves the verified identity a request runs under. It returns false
// when the request carries no usable session, which is the only thing this
// package will ever learn about why.
type Session interface {
	ReadContext(*http.Request) (aggregate.ReadContext, bool)
}

// Reader is the repository read port this surface shapes.
type Reader interface {
	Tree(ctx context.Context, read aggregate.ReadContext, revision, pageToken string, pageSize int) (aggregate.TreePage, error)
	File(ctx context.Context, read aggregate.ReadContext, revision, path string, send func(aggregate.FileChunk) error) error
	Diff(ctx context.Context, read aggregate.ReadContext, baseRevision, headRevision, path string, send func(aggregate.DiffChunk) error) error
	History(ctx context.Context, read aggregate.ReadContext, revision, path, pageToken string, pageSize int32) (aggregate.HistoryPage, error)
	Blame(ctx context.Context, read aggregate.ReadContext, revision, path string) (aggregate.BlameResult, error)
}

// Handler serves the browser view routes.
type Handler struct {
	reader  Reader
	session Session
}

func New(reader Reader, session Session) *Handler {
	return &Handler{reader: reader, session: session}
}

// fileMetadataHeader carries the one FileViewMetadata frame the contract puts
// before the bytes. HTTP has no notion of a first frame, so it travels as a
// header: sent once, before any body byte, and never repeated.
const fileMetadataHeader = "X-Gitfrok-File-Metadata"

// Routes returns the surface. The repository ID is a path handle; every other
// input is a query parameter, and none of them names identity.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/repositories/{repository_id}/tree", h.tree)
	mux.HandleFunc("GET /v1/repositories/{repository_id}/file", h.file)
	mux.HandleFunc("GET /v1/repositories/{repository_id}/diff", h.diff)
	mux.HandleFunc("GET /v1/repositories/{repository_id}/history", h.history)
	mux.HandleFunc("GET /v1/repositories/{repository_id}/blame", h.blame)
	return mux
}

func (h *Handler) tree(w http.ResponseWriter, r *http.Request) {
	read, revision, ok := h.begin(w, r)
	if !ok {
		return
	}
	pageSize, ok := pageSize(r.URL.Query().Get("page_size"))
	if !ok {
		unavailable(w)
		return
	}

	page, err := h.reader.Tree(r.Context(), read, revision, r.URL.Query().Get("page_token"), pageSize)
	if err != nil {
		unavailable(w)
		return
	}

	view := &bffv1.TreeView{NextPageToken: page.NextPageToken}
	for _, entry := range page.Entries {
		view.Entries = append(view.Entries, &bffv1.BrowserTreeEntry{
			Path: entry.Path, Kind: kind(entry.Kind), SizeBytes: entry.SizeBytes,
		})
	}
	body, err := protojson.Marshal(view)
	if err != nil {
		unavailable(w)
		return
	}
	private(w)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (h *Handler) file(w http.ResponseWriter, r *http.Request) {
	read, revision, ok := h.begin(w, r)
	if !ok {
		return
	}
	path, ok := repositoryPath(r.URL.Query().Get("path"))
	if !ok || path == "" {
		unavailable(w)
		return
	}

	// Nothing is written until the reader produces its first chunk. A failed read
	// must leave no partial body and no metadata behind (SPEC-0021).
	started := false
	err := h.reader.File(r.Context(), read, revision, path, func(chunk aggregate.FileChunk) error {
		if !started {
			if chunk.Metadata != nil {
				metadata, marshalErr := protojson.Marshal(&bffv1.FileViewMetadata{
					Path: chunk.Metadata.Path, Revision: revision, SizeBytes: chunk.Metadata.SizeBytes,
				})
				if marshalErr != nil {
					return marshalErr
				}
				w.Header().Set(fileMetadataHeader, string(metadata))
			}
			private(w)
			w.Header().Set("Content-Type", "application/octet-stream")
			started = true
		}
		return write(w, chunk.Data)
	})
	finish(w, started, err)
}

func (h *Handler) diff(w http.ResponseWriter, r *http.Request) {
	read, ok := h.identity(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	base, head := query.Get("base_revision"), query.Get("head_revision")
	if !validRevision(base) || !validRevision(head) {
		unavailable(w)
		return
	}
	// The path filter is optional here, unlike a file view, but an unusable one is
	// still a refusal rather than a filter silently dropped.
	path, ok := repositoryPath(query.Get("path"))
	if !ok {
		unavailable(w)
		return
	}

	started := false
	err := h.reader.Diff(r.Context(), read, base, head, path, func(chunk aggregate.DiffChunk) error {
		if !started {
			private(w)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			started = true
		}
		return write(w, chunk.Data)
	})
	finish(w, started, err)
}

// begin resolves the session and the revision every view needs.
func (h *Handler) begin(w http.ResponseWriter, r *http.Request) (aggregate.ReadContext, string, bool) {
	read, ok := h.identity(w, r)
	if !ok {
		return aggregate.ReadContext{}, "", false
	}
	revision := r.URL.Query().Get("revision")
	if !validRevision(revision) {
		unavailable(w)
		return aggregate.ReadContext{}, "", false
	}
	return read, revision, true
}

// identity takes the tenant and actor from the session and the repository from
// the route. A request that names its own tenant does not get a different answer;
// there is nowhere for it to name one.
func (h *Handler) identity(w http.ResponseWriter, r *http.Request) (aggregate.ReadContext, bool) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" || read.RequestID == "" {
		unauthenticated(w)
		return aggregate.ReadContext{}, false
	}
	repositoryID := r.PathValue("repository_id")
	if !validHandle(repositoryID) {
		unavailable(w)
		return aggregate.ReadContext{}, false
	}
	read.RepositoryID = repositoryID
	return read, true
}

// finish reports the outcome of a streamed view. Once bytes are on the wire the
// status is already sent, so a mid-stream failure ends the response rather than
// pretending it succeeded; a failure before the first byte is a clean refusal.
func finish(w http.ResponseWriter, started bool, err error) {
	switch {
	case err != nil && !started:
		unavailable(w)
	case err != nil:
		// The response is already committed. Flushing nothing further and
		// returning leaves a truncated body, which a client detects, rather than
		// a body that looks complete.
		if flusher, canFlush := w.(http.Flusher); canFlush {
			flusher.Flush()
		}
	case !started:
		// An empty file or an empty diff is still a successful, private response.
		private(w)
		w.WriteHeader(http.StatusOK)
	}
}

func write(w http.ResponseWriter, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if flusher, canFlush := w.(http.Flusher); canFlush {
		flusher.Flush()
	}
	return nil
}

// private marks every successful response uncacheable. Source is private, and a
// shared cache holding it is a cross-tenant leak waiting for a cache key bug.
func private(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
}

// unavailable is the one refusal this surface returns for anything about a
// repository. It distinguishes nothing — not a missing revision from a path
// outside the repository from another tenant's repository — because a browser
// -facing error that distinguished them would enumerate them.
func unavailable(w http.ResponseWriter) {
	private(w)
	http.Error(w, "repository view unavailable", http.StatusNotFound)
}

// unauthenticated is separate, and only separate, because "you are not logged in"
// is not information about any repository. It says nothing about what exists.
func unauthenticated(w http.ResponseWriter) {
	private(w)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// pageSize passes the caller's request through to the server, which owns the
// default and the cap (SPEC-0017). Absent means "server default".
func pageSize(value string) (int, bool) {
	if value == "" {
		return 0, true
	}
	size, err := strconv.Atoi(value)
	if err != nil || size < 0 {
		return 0, false
	}
	return size, true
}

// repositoryPath validates the path the query already decoded, and refuses
// anything that is not repository-relative.
//
// It does NOT decode again. net/url percent-decodes query values as it parses
// them, so a second decode here would turn "%252e%252e" — a literal "%2e%2e" the
// caller asked for — into "..", which is exactly the traversal this rejects. Once
// is the contract (SPEC-0021), and once is what has already happened.
//
// An absolute prefix, a traversal segment, a NUL, or a backslash is each an
// attempt to name something outside the repository. The value is passed on
// unchanged and never resolved against a filesystem, so refusing it here is the
// only place it can be refused before it becomes someone else's input.
func repositoryPath(decoded string) (string, bool) {
	if decoded == "" {
		return "", true
	}
	if strings.HasPrefix(decoded, "/") || strings.HasPrefix(decoded, "\\") ||
		strings.Contains(decoded, "\x00") || strings.Contains(decoded, "\\") ||
		strings.Contains(decoded, "//") || len(decoded) > 4096 {
		return "", false
	}
	for segment := range strings.SplitSeq(decoded, "/") {
		if segment == "." || segment == ".." {
			return "", false
		}
	}
	return decoded, true
}

// validRevision accepts an opaque revision handle and nothing that git would
// reinterpret as an option or a range.
func validRevision(value string) bool {
	if value == "" || len(value) > 256 || strings.HasPrefix(value, "-") ||
		strings.Contains(value, "..") || strings.ContainsAny(value, "\\\x00 \t\n\r~^:?*[") {
		return false
	}
	return true
}

// validHandle accepts the opaque repository identifiers the backend issues.
func validHandle(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case (r == '-' || r == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

func kind(entry aggregate.EntryKind) bffv1.BrowserEntryKind {
	switch entry {
	case aggregate.EntryFile:
		return bffv1.BrowserEntryKind_BROWSER_ENTRY_KIND_FILE
	case aggregate.EntryDirectory:
		return bffv1.BrowserEntryKind_BROWSER_ENTRY_KIND_DIRECTORY
	case aggregate.EntrySymlink:
		return bffv1.BrowserEntryKind_BROWSER_ENTRY_KIND_SYMLINK
	default:
		return bffv1.BrowserEntryKind_BROWSER_ENTRY_KIND_UNSPECIFIED
	}
}

// --- history and blame (T-0057, SPEC-0053 AC9) ----------------------------
//
// Every identity field keeps its git_ prefix through the JSON. That is the
// point at which a consumer decides what a name means, and a field called
// "author" would let the layer above render an unverified string as an
// account. The platform knows who PUSHED; it does not know who this says wrote
// the line, and the naming carries that all the way to the browser.

// CommitIdentityView is git's word for who authored and committed.
type CommitIdentityView struct {
	GitAuthorName     string `json:"git_author_name"`
	GitAuthorEmail    string `json:"git_author_email"`
	GitCommitterName  string `json:"git_committer_name"`
	GitCommitterEmail string `json:"git_committer_email"`
	AuthoredAt        string `json:"authored_at"`
	CommittedAt       string `json:"committed_at"`
}

// CommitView is one entry of a ref's history.
type CommitView struct {
	CommitID string             `json:"commit_id"`
	Identity CommitIdentityView `json:"identity"`
	Subject  string             `json:"subject"`
}

// HistoryView is one page of commits. It carries no total: the walk has no end
// the server has counted, and a figure here would be invented.
type HistoryView struct {
	Commits       []CommitView `json:"commits"`
	NextPageToken string       `json:"next_page_token"`
}

// BlameRangeView is one contiguous run of lines attributed to one commit.
type BlameRangeView struct {
	StartLine int32              `json:"start_line"`
	EndLine   int32              `json:"end_line"`
	CommitID  string             `json:"commit_id"`
	Identity  CommitIdentityView `json:"identity"`
}

// BlameView carries the ranges and whether the file outran the server's cap.
type BlameView struct {
	Ranges []BlameRangeView `json:"ranges"`
	Capped bool             `json:"capped"`
}

func identityView(i aggregate.CommitIdentity) CommitIdentityView {
	return CommitIdentityView{
		GitAuthorName:     i.GitAuthorName,
		GitAuthorEmail:    i.GitAuthorEmail,
		GitCommitterName:  i.GitCommitterName,
		GitCommitterEmail: i.GitCommitterEmail,
		AuthoredAt:        i.AuthoredAt,
		CommittedAt:       i.CommittedAt,
	}
}

func (h *Handler) history(w http.ResponseWriter, r *http.Request) {
	read, revision, ok := h.begin(w, r)
	if !ok {
		return
	}
	size, ok := pageSize(r.URL.Query().Get("page_size"))
	if !ok {
		unavailable(w)
		return
	}
	page, err := h.reader.History(r.Context(), read, revision,
		r.URL.Query().Get("path"), r.URL.Query().Get("page_token"), int32(size))
	if err != nil {
		unavailable(w)
		return
	}
	view := HistoryView{Commits: make([]CommitView, 0, len(page.Commits)), NextPageToken: page.NextPageToken}
	for _, commit := range page.Commits {
		view.Commits = append(view.Commits, CommitView{
			CommitID: commit.CommitID, Identity: identityView(commit.Identity), Subject: commit.Subject,
		})
	}
	writeJSONView(w, view)
}

func (h *Handler) blame(w http.ResponseWriter, r *http.Request) {
	read, revision, ok := h.begin(w, r)
	if !ok {
		return
	}
	result, err := h.reader.Blame(r.Context(), read, revision, r.URL.Query().Get("path"))
	if err != nil {
		unavailable(w)
		return
	}
	view := BlameView{Ranges: make([]BlameRangeView, 0, len(result.Ranges)), Capped: result.Capped}
	for _, rng := range result.Ranges {
		view.Ranges = append(view.Ranges, BlameRangeView{
			StartLine: rng.StartLine, EndLine: rng.EndLine, CommitID: rng.CommitID,
			Identity: identityView(rng.Identity),
		})
	}
	writeJSONView(w, view)
}

// writeJSONView emits a plain-JSON view. The tree and file surfaces marshal
// protobuf views through protojson; these two are BFF-shaped structs, so they
// go out as ordinary JSON with the same private, no-store posture.
func writeJSONView(w http.ResponseWriter, view any) {
	body, err := json.Marshal(view)
	if err != nil {
		unavailable(w)
		return
	}
	private(w)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
