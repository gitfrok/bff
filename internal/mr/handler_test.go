package mr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/codereview"
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
		TenantID: "tenant-a", ActorID: "actor-a", RequestID: "request-a",
	}}
}

type stubClient struct {
	mr  *codereview.MergeRequest
	err error
}

func (s *stubClient) Get(_ context.Context, _ aggregate.ReadContext, _ string) (*codereview.MergeRequest, error) {
	return s.mr, s.err
}

func (s *stubClient) Create(_ context.Context, _ aggregate.ReadContext, _, _, title, _ string) (*codereview.MergeRequest, error) {
	return &codereview.MergeRequest{MergeRequestID: "mr-1", Title: title, State: "OPEN", Version: 1, CreatedAt: time.Now()}, s.err
}

func (s *stubClient) SubmitReview(_ context.Context, _ aggregate.ReadContext, _, _, _, _ string, _ int64) (*codereview.MergeRequest, error) {
	return s.mr, s.err
}

func (s *stubClient) Merge(_ context.Context, _ aggregate.ReadContext, _ string, _ int64) (*codereview.MergeRequest, error) {
	return s.mr, s.err
}

func serve(t *testing.T, s Session, c MergeRequests, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	New(c, s).Routes().ServeHTTP(recorder, httptest.NewRequest(method, target, nil))
	return recorder
}

// A merge request view is served from the session's identity only, and the
// response carries review state without any policy outcome.
func TestGetMergeRequest(t *testing.T) {
	c := &stubClient{mr: &codereview.MergeRequest{
		MergeRequestID: "mr-1", RepositoryID: "repo-a", SourceRef: "refs/heads/topic",
		TargetRef: "refs/heads/main", Title: "Add feature", State: "OPEN", Version: 3,
	}}
	response := serve(t, session(), c, http.MethodGet, "/v1/repositories/repo-a/merge_requests/mr-1")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"mr-1"`) || !strings.Contains(body, "Add feature") || !strings.Contains(body, "OPEN") {
		t.Fatalf("body = %s", body)
	}
	if strings.Contains(body, "allowed") || strings.Contains(body, "approval") {
		t.Fatalf("body leaked a policy outcome: %s", body)
	}
}

// A request without a session is refused and never reaches the client.
func TestNoSessionIsRefused(t *testing.T) {
	c := &stubClient{mr: &codereview.MergeRequest{}}
	response := serve(t, stubSession{}, c, http.MethodGet, "/v1/repositories/repo-a/merge_requests/mr-1")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
	if c.mr == nil {
		t.Fatal("client was called without a session")
	}
}

// A client refusal is the one coarse denial; it says nothing about what exists.
func TestClientRefusalIsCoarse(t *testing.T) {
	c := &stubClient{err: context.DeadlineExceeded}
	response := serve(t, session(), c, http.MethodGet, "/v1/repositories/repo-a/merge_requests/mr-1")
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}
