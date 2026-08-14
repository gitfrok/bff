package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/search"
)

// stubSession is the authenticated session the middleware would install.
type stubSession struct {
	read    aggregate.ReadContext
	present bool
}

func (s stubSession) ReadContext(*http.Request) (aggregate.ReadContext, bool) {
	return s.read, s.present
}

func session() stubSession {
	return stubSession{present: true, read: aggregate.ReadContext{
		TenantID: "tenant-a", ActorID: "actor-a", ActorRoles: []string{"member"},
	}}
}

// stubSearcher records the identity it was handed and answers with a canned page.
type stubSearcher struct {
	read   aggregate.ReadContext
	query  search.Query
	page   search.Page
	status []search.IndexStatus
	err    error
	calls  int
}

func (s *stubSearcher) Search(_ context.Context, read aggregate.ReadContext, q search.Query) (search.Page, error) {
	s.read, s.query, s.calls = read, q, s.calls+1
	return s.page, s.err
}

func (s *stubSearcher) IndexStatus(_ context.Context, read aggregate.ReadContext) ([]search.IndexStatus, error) {
	s.read, s.calls = read, s.calls+1
	return s.status, s.err
}

// stubFiles answers enrichment reads with one metadata frame, or refuses.
type stubFiles struct {
	read aggregate.ReadContext
	meta *aggregate.FileMetadata
	err  error
}

func (s *stubFiles) File(_ context.Context, read aggregate.ReadContext, _, _ string, send func(aggregate.FileChunk) error) error {
	s.read = read
	if s.err != nil {
		return s.err
	}
	return send(aggregate.FileChunk{Metadata: s.meta})
}

func serve(t *testing.T, h *SearchHandler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	h.Routes().ServeHTTP(recorder, httptest.NewRequest(method, target, reader))
	return recorder
}

const queryBody = `{"query":"func main","mode":"SUBSTRING","result_limit":10,"context_line_limit":2,"page_token":"tok"}`

// A query is answered with the backend's authorized page, enriched with the
// file metadata Repository/Git serves, and nothing else: no count, no score,
// no policy outcome.
func TestQueryShapesResultsWithMetadata(t *testing.T) {
	searcher := &stubSearcher{page: search.Page{
		Results: []search.Result{{
			RepositoryID: "repo-a", Revision: "rev-1", Path: "main.go",
			LineStart: 3, LineEnd: 5, MatchedContent: "func main",
		}},
		NextPageToken: "next",
	}}
	files := &stubFiles{meta: &aggregate.FileMetadata{Path: "main.go", ObjectID: "blob-1", Mode: 0o100644, SizeBytes: 42}}
	response := serve(t, NewSearch(searcher, files, session()), http.MethodPost, "/api/v1/search/query", queryBody)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{`"repo-a"`, `"rev-1"`, `"main.go"`, `"func main"`, `"blob-1"`, `"size_bytes":42`, `"next_page_token":"next"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, "allowed") || strings.Contains(body, "score") || strings.Contains(body, "total") {
		t.Fatalf("body leaked a policy or ranking outcome: %s", body)
	}
	if searcher.query.Text != "func main" || searcher.query.Mode != search.ModeSubstring ||
		searcher.query.ResultLimit != 10 || searcher.query.ContextLineLimit != 2 || searcher.query.PageToken != "tok" {
		t.Fatalf("query = %+v", searcher.query)
	}
	// Identity came from the session, and enrichment ran under the result's
	// repository with the same verified tenant and actor.
	if searcher.read.TenantID != "tenant-a" || searcher.read.ActorID != "actor-a" || searcher.read.RequestID == "" {
		t.Fatalf("search context = %+v", searcher.read)
	}
	if files.read.RepositoryID != "repo-a" || files.read.TenantID != "tenant-a" || files.read.ActorID != "actor-a" {
		t.Fatalf("enrichment context = %+v", files.read)
	}
}

// The BFF shapes; it does not rank. Results leave in the backend's order.
func TestQueryPreservesBackendOrder(t *testing.T) {
	searcher := &stubSearcher{page: search.Page{Results: []search.Result{
		{RepositoryID: "repo-b", Path: "z.go"},
		{RepositoryID: "repo-a", Path: "a.go"},
	}}}
	response := serve(t, NewSearch(searcher, nil, session()), http.MethodPost, "/api/v1/search/query", queryBody)
	body := response.Body.String()
	if response.Code != http.StatusOK || strings.Index(body, "repo-b") > strings.Index(body, "repo-a") {
		t.Fatalf("order not preserved: %s", body)
	}
	if strings.Contains(body, `"metadata"`) {
		t.Fatalf("results carried metadata without an enrichment port: %s", body)
	}
}

// The empty page is the one shape a no-match query and an unauthorized-only
// query both return: results present and empty, no distinguishing field
// (SPEC-0035 AC4).
func TestQueryEmptyPageShape(t *testing.T) {
	searcher := &stubSearcher{page: search.Page{Results: []search.Result{}}}
	response := serve(t, NewSearch(searcher, nil, session()), http.MethodPost, "/api/v1/search/query", queryBody)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := strings.TrimSpace(response.Body.String())
	if body != `{"results":[],"next_page_token":""}` {
		t.Fatalf("body = %s", body)
	}
}

// A request without a session is refused and never reaches the backend.
func TestQueryWithoutSessionIsRefused(t *testing.T) {
	searcher := &stubSearcher{}
	response := serve(t, NewSearch(searcher, nil, stubSession{}), http.MethodPost, "/api/v1/search/query", queryBody)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if searcher.calls != 0 {
		t.Fatal("backend was called without a session")
	}
}

// A backend refusal is the one coarse denial; it says nothing about what
// exists or why (SPEC-0001).
func TestQueryBackendRefusalIsCoarse(t *testing.T) {
	searcher := &stubSearcher{err: context.DeadlineExceeded}
	response := serve(t, NewSearch(searcher, nil, session()), http.MethodPost, "/api/v1/search/query", queryBody)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if !strings.Contains(response.Body.String(), "search unavailable") {
		t.Fatalf("body = %s", response.Body.String())
	}
}

// Enrichment is shaping, not filtering: a reader refusal serves the
// authorized result without metadata instead of deciding anything about it.
func TestQueryEnrichmentFailureStillServesResult(t *testing.T) {
	searcher := &stubSearcher{page: search.Page{Results: []search.Result{
		{RepositoryID: "repo-a", Revision: "rev-1", Path: "main.go", MatchedContent: "func main"},
	}}}
	files := &stubFiles{err: errors.New("repository unavailable")}
	response := serve(t, NewSearch(searcher, files, session()), http.MethodPost, "/api/v1/search/query", queryBody)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"repo-a"`) || strings.Contains(body, `"metadata"`) {
		t.Fatalf("body = %s", body)
	}
}

// A malformed body and an unnamed mode are the same coarse refusal as
// everything else, and neither reaches the backend.
func TestQueryMalformedInputIsCoarse(t *testing.T) {
	for _, body := range []string{
		`{not json`,
		`{"query":"x","mode":"EVERYTHING"}`,
		`{"query":"x"}`,
	} {
		searcher := &stubSearcher{page: search.Page{Results: []search.Result{}}}
		response := serve(t, NewSearch(searcher, nil, session()), http.MethodPost, "/api/v1/search/query", body)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", body, response.Code)
		}
		if searcher.calls != 0 {
			t.Fatalf("%s: backend was called for a malformed request", body)
		}
	}
}

// Status is shaped from the backend's entries: which repositories appear is
// the backend's decision, and the BFF adds nothing to it.
func TestStatusShapesEntries(t *testing.T) {
	when := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	searcher := &stubSearcher{status: []search.IndexStatus{{
		RepositoryID: "repo-a", LastIndexedRevision: "rev-9",
		IndexedAt: when, FreshnessLag: 1500 * time.Millisecond,
	}}}
	response := serve(t, NewSearch(searcher, nil, session()), http.MethodGet, "/api/v1/search/status", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{`"repo-a"`, `"rev-9"`, `"freshness_lag_ms":1500`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	if searcher.read.TenantID != "tenant-a" || searcher.read.ActorID != "actor-a" || searcher.read.RequestID == "" {
		t.Fatalf("context = %+v", searcher.read)
	}
}

// Status without a session, and a status refusal, are the same coarse shape.
func TestStatusRefusalsAreCoarse(t *testing.T) {
	searcher := &stubSearcher{}
	if response := serve(t, NewSearch(searcher, nil, stubSession{}), http.MethodGet, "/api/v1/search/status", ""); response.Code != http.StatusNotFound {
		t.Fatalf("no session: status = %d, want 404", response.Code)
	}
	if searcher.calls != 0 {
		t.Fatal("backend was called without a session")
	}
	refusing := &stubSearcher{err: context.DeadlineExceeded}
	if response := serve(t, NewSearch(refusing, nil, session()), http.MethodGet, "/api/v1/search/status", ""); response.Code != http.StatusNotFound {
		t.Fatalf("refusal: status = %d, want 404", response.Code)
	}
}
