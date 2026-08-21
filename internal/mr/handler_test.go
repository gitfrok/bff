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
	// What the create and ready routes forwarded (ADR-0087, SPEC-0064).
	createdDraft bool
	readyID      string
	readyVersion int64
	// What the external-issue routes forwarded (SPEC-0059).
	linked     codereview.ExternalIssue
	unlinked   codereview.ExternalIssue
	linkedTo   string
	linkedRead aggregate.ReadContext
}

func (s *stubClient) Get(_ context.Context, _ aggregate.ReadContext, _ string) (*codereview.MergeRequest, error) {
	return s.mr, s.err
}

func (s *stubClient) Create(_ context.Context, _ aggregate.ReadContext, _, _, title, _ string, draft bool) (*codereview.MergeRequest, error) {
	s.createdDraft = draft
	state := "OPEN"
	if draft {
		state = "MERGE_REQUEST_STATE_DRAFT"
	}
	return &codereview.MergeRequest{MergeRequestID: "mr-1", Title: title, State: state, Version: 1, CreatedAt: time.Now()}, s.err
}

func (s *stubClient) SubmitReview(_ context.Context, _ aggregate.ReadContext, _, _, _, _ string, _ int64) (*codereview.MergeRequest, error) {
	return s.mr, s.err
}

func (s *stubClient) Merge(_ context.Context, _ aggregate.ReadContext, _ string, _ int64) (*codereview.MergeRequest, error) {
	return s.mr, s.err
}

func (s *stubClient) MarkReady(_ context.Context, _ aggregate.ReadContext, mergeRequestID string, expectedVersion int64) (*codereview.MergeRequest, error) {
	s.readyID, s.readyVersion = mergeRequestID, expectedVersion
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

// The create route forwards the draft flag (ADR-0087, SPEC-0064): checked-on
// means DRAFT, absent means OPEN exactly as before.
func TestCreateForwardsTheDraftFlag(t *testing.T) {
	sess := session()
	for _, tc := range []struct{ form, want string }{
		{"source_ref=refs/heads/topic&target_ref=refs/heads/main&title=T&draft=on", "MERGE_REQUEST_STATE_DRAFT"},
		{"source_ref=refs/heads/topic&target_ref=refs/heads/main&title=T", "OPEN"},
	} {
		c := &stubClient{}
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/repositories/repo-a/merge_requests", strings.NewReader(tc.form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		New(c, nil, sess).Routes().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("create status = %d", recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), tc.want) {
			t.Fatalf("draft=%q: body = %s, want state %s", tc.form, recorder.Body.String(), tc.want)
		}
		if c.createdDraft != (tc.want == "MERGE_REQUEST_STATE_DRAFT") {
			t.Fatalf("draft flag forwarded as %v for %q", c.createdDraft, tc.form)
		}
	}
}

// The ready route forwards the ID and expected version, shaped like merge.
func TestReadyRouteForwards(t *testing.T) {
	c := &stubClient{mr: &codereview.MergeRequest{MergeRequestID: "mr-9", State: "OPEN", Version: 4}}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/repositories/repo-a/merge_requests/mr-9/ready", strings.NewReader("expected_version=3"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	New(c, nil, session()).Routes().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("ready status = %d", recorder.Code)
	}
	if c.readyID != "mr-9" || c.readyVersion != 3 {
		t.Fatalf("ready forwarded id=%q version=%d", c.readyID, c.readyVersion)
	}
}
