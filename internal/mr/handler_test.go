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
	// What the external-issue routes forwarded (SPEC-0059).
	linked     codereview.ExternalIssue
	unlinked   codereview.ExternalIssue
	linkedTo   string
	linkedRead aggregate.ReadContext
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

// The external-issue methods are on the port, so the stub fills them (SPEC-0059).
// It records what it was asked, because what this layer forwards is the whole of what
// it is responsible for.
func (s *stubClient) LinkExternalIssue(_ context.Context, read aggregate.ReadContext, mergeRequestID, tracker, issueKey, issueURL string) (*codereview.MergeRequest, error) {
	s.linkedRead = read
	s.linked = codereview.ExternalIssue{Tracker: tracker, IssueKey: issueKey, URL: issueURL}
	s.linkedTo = mergeRequestID
	if s.err != nil {
		return nil, s.err
	}
	return s.mr, nil
}

func (s *stubClient) UnlinkExternalIssue(_ context.Context, read aggregate.ReadContext, mergeRequestID, tracker, issueKey string) (*codereview.MergeRequest, error) {
	s.linkedRead = read
	s.unlinked = codereview.ExternalIssue{Tracker: tracker, IssueKey: issueKey}
	s.linkedTo = mergeRequestID
	if s.err != nil {
		return nil, s.err
	}
	return s.mr, nil
}

func serve(t *testing.T, s Session, c MergeRequests, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	New(c, nil, s).Routes().ServeHTTP(recorder, httptest.NewRequest(method, target, nil))
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
