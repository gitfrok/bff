package mr

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/codereview"
)

type stubImports struct {
	page     codereview.ImportedHistoryPage
	err      error
	read     aggregate.ReadContext
	importID string
	pageSize int32
	token    string
	calls    int
}

func (s *stubImports) ListImportedHistory(_ context.Context, read aggregate.ReadContext, importID string, pageSize int32, pageToken string) (codereview.ImportedHistoryPage, error) {
	s.calls++
	s.read, s.importID, s.pageSize, s.token = read, importID, pageSize, pageToken
	return s.page, s.err
}

func serveImports(t *testing.T, s Session, imports ImportedHistory, target string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	New(&stubClient{}, imports, s).Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder
}

func declaredTimeFixture() time.Time {
	return time.Date(2019, 4, 2, 9, 30, 0, 0, time.UTC)
}

func importedPage() codereview.ImportedHistoryPage {
	provenance := codereview.Provenance{
		Class:          codereview.ClassImported,
		ImportID:       "import-1",
		SourceSystem:   "github",
		SourceInstance: "github.com",
		SourceRef:      "https://github.com/acme/widget/pull/7",
		DeclaredActor:  "octocat",
		DeclaredAt:     declaredTimeFixture(),
		PayloadDigest:  "sha256:abc",
	}
	return codereview.ImportedHistoryPage{
		NextPageToken: "page-2",
		MergeRequests: []codereview.ImportedMergeRequest{{
			MergeRequestID:  "imported-7",
			SourceRef:       "refs/heads/topic",
			TargetRef:       "refs/heads/main",
			Title:           "Old pull request",
			Description:     "from GitHub",
			State:           "merged",
			DeclaredCreator: "octocat",
			Provenance:      provenance,
			Threads: []codereview.ImportedThread{{
				ThreadID:       "thread-1",
				MergeRequestID: "imported-7",
				Path:           "cmd/main.go",
				Anchor:         codereview.AnchorFile,
				Provenance:     provenance,
				Comments: []codereview.ImportedComment{{
					CommentID:     "comment-1",
					DeclaredActor: "octocat",
					Body:          "looks fine to me",
					DeclaredAt:    declaredTimeFixture(),
					Provenance:    provenance,
				}},
			}},
			Approvals: []codereview.ImportedApproval{{
				ApprovalID:     "approval-1",
				MergeRequestID: "imported-7",
				DeclaredActor:  "hubber",
				DeclaredAt:     declaredTimeFixture(),
				Provenance:     provenance,
			}},
		}},
	}
}

func decodeHistory(t *testing.T, recorder *httptest.ResponseRecorder) ImportedHistoryView {
	t.Helper()
	var view ImportedHistoryView
	if err := json.Unmarshal(recorder.Body.Bytes(), &view); err != nil {
		t.Fatalf("body is not the history view: %v", err)
	}
	return view
}

// Every imported record reaches the browser carrying its provenance class, so a
// page can tell imported history from first-party history (SPEC-0011 AC23).
func TestImportedHistoryCarriesProvenanceOnEveryRecord(t *testing.T) {
	imports := &stubImports{page: importedPage()}
	response := serveImports(t, session(), imports, "/v1/repositories/repo-a/imports/import-1/history")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	view := decodeHistory(t, response)
	if len(view.MergeRequests) != 1 {
		t.Fatalf("merge requests = %d", len(view.MergeRequests))
	}
	mr := view.MergeRequests[0]
	classes := []string{mr.Provenance.Class}
	for _, thread := range mr.Threads {
		classes = append(classes, thread.Provenance.Class)
		for _, comment := range thread.Comments {
			classes = append(classes, comment.Provenance.Class)
		}
	}
	for _, approval := range mr.Approvals {
		classes = append(classes, approval.Provenance.Class)
	}
	if len(classes) != 4 {
		t.Fatalf("provenance blocks = %d, want one per record", len(classes))
	}
	for _, class := range classes {
		if class != codereview.ClassImported {
			t.Fatalf("class = %q, want %q on every imported record", class, codereview.ClassImported)
		}
	}
	if view.NextPageToken != "page-2" {
		t.Fatalf("next page token = %q", view.NextPageToken)
	}
}

// An imported approval is never presentable as a platform approval: the view
// states that it satisfies no policy, and it carries a declared actor rather
// than a resolvable platform identity (SPEC-0011 AC13/AC14, ADR-0029 §4).
func TestImportedApprovalIsNeverAPlatformApproval(t *testing.T) {
	imports := &stubImports{page: importedPage()}
	response := serveImports(t, session(), imports, "/v1/repositories/repo-a/imports/import-1/history")
	view := decodeHistory(t, response)
	approval := view.MergeRequests[0].Approvals[0]
	if approval.SatisfiesPolicy {
		t.Fatal("an imported approval claimed to satisfy a merge policy")
	}
	if approval.DeclaredActor != "hubber" {
		t.Fatalf("declared actor = %q", approval.DeclaredActor)
	}
	body := response.Body.String()
	for _, forbidden := range []string{`"actor_id"`, `"approver_id"`, `"creator_id"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("body resolves a foreign handle as a platform actor (%s): %s", forbidden, body)
		}
	}
}

// A thread whose diff position no longer resolves is marked approximate, so the
// page cannot render a degraded anchor as an exact one (SPEC-0011 AC5).
func TestDegradedAnchorIsMarkedApproximate(t *testing.T) {
	page := importedPage()
	imports := &stubImports{page: page}
	view := decodeHistory(t, serveImports(t, session(), imports, "/v1/repositories/repo-a/imports/import-1/history"))
	thread := view.MergeRequests[0].Threads[0]
	if thread.Anchor != codereview.AnchorFile || !thread.Approximate {
		t.Fatalf("anchor = %q approximate = %v, want FILE and approximate", thread.Anchor, thread.Approximate)
	}

	page.MergeRequests[0].Threads[0].Anchor = codereview.AnchorDiff
	view = decodeHistory(t, serveImports(t, session(), &stubImports{page: page}, "/v1/repositories/repo-a/imports/import-1/history"))
	if view.MergeRequests[0].Threads[0].Approximate {
		t.Fatal("a thread anchored to a diff position was marked approximate")
	}
}

// A revoked import returns nothing, and the empty page is an empty list rather
// than JSON null, so a reader never has to distinguish the two.
func TestRevokedImportReturnsAnEmptyPage(t *testing.T) {
	imports := &stubImports{page: codereview.ImportedHistoryPage{}}
	response := serveImports(t, session(), imports, "/v1/repositories/repo-a/imports/import-1/history")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), `"merge_requests":[]`) {
		t.Fatalf("body = %s", response.Body.String())
	}
}

// The tenant and the actor come only from the session; the path contributes the
// repository and the import, and nothing else.
func TestImportedHistoryIdentityComesFromTheSession(t *testing.T) {
	imports := &stubImports{page: importedPage()}
	serveImports(t, session(), imports, "/v1/repositories/repo-a/imports/import-1/history?page_size=50&page_token=page-1")
	if imports.read.TenantID != "tenant-a" || imports.read.ActorID != "actor-a" {
		t.Fatalf("read context = %+v", imports.read)
	}
	if imports.read.RepositoryID != "repo-a" || imports.importID != "import-1" {
		t.Fatalf("repository = %q import = %q", imports.read.RepositoryID, imports.importID)
	}
	if imports.pageSize != 50 || imports.token != "page-1" {
		t.Fatalf("page size = %d token = %q", imports.pageSize, imports.token)
	}
}

// A request without a session never reaches the import port.
func TestImportedHistoryWithoutSessionIsRefused(t *testing.T) {
	imports := &stubImports{page: importedPage()}
	response := serveImports(t, stubSession{}, imports, "/v1/repositories/repo-a/imports/import-1/history")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if imports.calls != 0 {
		t.Fatal("the import port was called without a session")
	}
}

// A page size the surface will not serve is refused rather than clamped: a
// caller told nothing would believe it received the page it asked for.
func TestOversizedPageSizeIsRefused(t *testing.T) {
	imports := &stubImports{page: importedPage()}
	response := serveImports(t, session(), imports, "/v1/repositories/repo-a/imports/import-1/history?page_size=100000")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if imports.calls != 0 {
		t.Fatal("an oversized page size reached the import port")
	}
}

// A backend refusal is the same coarse denial the rest of this surface returns.
func TestImportedHistoryRefusalIsCoarse(t *testing.T) {
	imports := &stubImports{err: context.DeadlineExceeded}
	response := serveImports(t, session(), imports, "/v1/repositories/repo-a/imports/import-1/history")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if body := response.Body.String(); strings.Contains(body, "deadline") {
		t.Fatalf("denial leaked the backend error: %s", body)
	}
}

// A deployment with no import port refuses the route instead of serving an empty
// page, which a reader would read as "this import has no history".
func TestNoImportPortRefuses(t *testing.T) {
	response := serveImports(t, session(), nil, "/v1/repositories/repo-a/imports/import-1/history")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}

// An absent source-declared time is JSON null, never the zero time.
func TestAbsentDeclaredAtIsNull(t *testing.T) {
	page := importedPage()
	page.MergeRequests[0].Threads[0].Comments[0].DeclaredAt = time.Time{}
	response := serveImports(t, session(), &stubImports{page: page}, "/v1/repositories/repo-a/imports/import-1/history")
	if strings.Contains(response.Body.String(), "0001-01-01") {
		t.Fatalf("body rendered the zero time: %s", response.Body.String())
	}
	view := decodeHistory(t, response)
	if view.MergeRequests[0].Threads[0].Comments[0].DeclaredAt != nil {
		t.Fatal("an absent declared_at became a date")
	}
}
