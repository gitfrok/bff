package search

import (
	"context"
	"errors"
	"testing"
	"time"

	searchv1 "github.com/gitfrok/bff/gen/proto/search/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeService records what crossed the wire and answers with canned responses.
type fakeService struct {
	searchReq  *searchv1.SearchRequest
	statusReq  *searchv1.GetIndexStatusRequest
	searchResp *searchv1.SearchResponse
	statusResp *searchv1.GetIndexStatusResponse
	err        error
}

func (f *fakeService) Search(_ context.Context, req *searchv1.SearchRequest, _ ...grpc.CallOption) (*searchv1.SearchResponse, error) {
	f.searchReq = req
	return f.searchResp, f.err
}

func (f *fakeService) GetIndexStatus(_ context.Context, req *searchv1.GetIndexStatusRequest, _ ...grpc.CallOption) (*searchv1.GetIndexStatusResponse, error) {
	f.statusReq = req
	return f.statusResp, f.err
}

func read() aggregate.ReadContext {
	return aggregate.ReadContext{
		TenantID: "tenant-a", ActorID: "actor-a", RequestID: "request-a",
		ActorRoles: []string{"member"},
	}
}

// The wire context carries exactly the session's verified identity — tenant,
// actor, roles, request ID — and the contract gives it no field to assert a
// repository set or a permission claim (SPEC-0035 AC2).
func TestSearchForwardsIdentityOnly(t *testing.T) {
	f := &fakeService{searchResp: &searchv1.SearchResponse{}}
	client := New(f)
	_, err := client.Search(context.Background(), read(), Query{
		Text: "func main", Mode: ModeSubstring, ResultLimit: 10, ContextLineLimit: 2, PageToken: "tok",
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	ctx := f.searchReq.GetContext()
	if ctx.GetTenantId() != "tenant-a" || ctx.GetActorId() != "actor-a" || ctx.GetRequestId() != "request-a" {
		t.Fatalf("context = %v", ctx)
	}
	//arch:allow-inline-authz this compares a forwarded role string for equality in a test; it grants nothing
	if len(ctx.GetActorRoles()) != 1 || ctx.GetActorRoles()[0] != "member" {
		t.Fatalf("roles = %v", ctx.GetActorRoles())
	}
	if f.searchReq.GetQuery() != "func main" || f.searchReq.GetResultLimit() != 10 ||
		f.searchReq.GetContextLineLimit() != 2 || f.searchReq.GetPageToken() != "tok" {
		t.Fatalf("request = %v", f.searchReq)
	}
	if f.searchReq.GetMode() != searchv1.QueryMode_QUERY_MODE_SUBSTRING {
		t.Fatalf("mode = %v", f.searchReq.GetMode())
	}
}

// Every named mode maps onto its contract enum.
func TestSearchModes(t *testing.T) {
	for mode, want := range map[Mode]searchv1.QueryMode{
		ModeSubstring: searchv1.QueryMode_QUERY_MODE_SUBSTRING,
		ModeRegex:     searchv1.QueryMode_QUERY_MODE_REGEX,
		ModeSymbol:    searchv1.QueryMode_QUERY_MODE_SYMBOL,
	} {
		f := &fakeService{searchResp: &searchv1.SearchResponse{}}
		if _, err := New(f).Search(context.Background(), read(), Query{Text: "x", Mode: mode}); err != nil {
			t.Fatalf("%s: err = %v", mode, err)
		}
		if f.searchReq.GetMode() != want {
			t.Fatalf("%s: wire mode = %v, want %v", mode, f.searchReq.GetMode(), want)
		}
	}
}

// A mode the contract does not name never reaches the backend.
func TestSearchUnknownModeIsMalformed(t *testing.T) {
	f := &fakeService{}
	_, err := New(f).Search(context.Background(), read(), Query{Text: "x", Mode: Mode("EVERYTHING")})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	if f.searchReq != nil {
		t.Fatal("backend was called for an unnamed mode")
	}
}

// The authorized page is shaped field for field; the adapter adds nothing
// and drops nothing.
func TestSearchShapesPage(t *testing.T) {
	f := &fakeService{searchResp: &searchv1.SearchResponse{
		Results: []*searchv1.SearchResult{{
			RepositoryId: "repo-a", Revision: "rev-1", Path: "main.go",
			LineStart: 3, LineEnd: 5, MatchedContent: "func main",
		}},
		NextPageToken: "next",
	}}
	page, err := New(f).Search(context.Background(), read(), Query{Text: "x", Mode: ModeSubstring})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if page.NextPageToken != "next" || len(page.Results) != 1 {
		t.Fatalf("page = %+v", page)
	}
	got := page.Results[0]
	if got.RepositoryID != "repo-a" || got.Revision != "rev-1" || got.Path != "main.go" ||
		got.LineStart != 3 || got.LineEnd != 5 || got.MatchedContent != "func main" {
		t.Fatalf("result = %+v", got)
	}
}

// A backend refusal passes through untouched; the coarse shape is applied by
// the HTTP surface, never by rewriting the reason here.
func TestSearchBackendErrorPassesThrough(t *testing.T) {
	refusal := errors.New("search: unavailable")
	_, err := New(&fakeService{err: refusal}).Search(context.Background(), read(), Query{Text: "x", Mode: ModeSubstring})
	if !errors.Is(err, refusal) {
		t.Fatalf("err = %v", err)
	}
}

// Freshness entries are shaped field for field; which repositories appear is
// the backend's decision, and the adapter cannot ask about others.
func TestIndexStatusShapesEntries(t *testing.T) {
	when := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	f := &fakeService{statusResp: &searchv1.GetIndexStatusResponse{
		Entries: []*searchv1.IndexStatusEntry{{
			RepositoryId: "repo-a", LastIndexedRevision: "rev-9",
			IndexedAt: timestamppb.New(when), FreshnessLag: durationpb.New(1500 * time.Millisecond),
		}},
	}}
	entries, err := New(f).IndexStatus(context.Background(), read())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if f.statusReq.GetContext().GetTenantId() != "tenant-a" || f.statusReq.GetContext().GetActorId() != "actor-a" {
		t.Fatalf("context = %v", f.statusReq.GetContext())
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %+v", entries)
	}
	got := entries[0]
	if got.RepositoryID != "repo-a" || got.LastIndexedRevision != "rev-9" ||
		!got.IndexedAt.Equal(when) || got.FreshnessLag != 1500*time.Millisecond {
		t.Fatalf("entry = %+v", got)
	}
}
