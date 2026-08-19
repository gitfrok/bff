package mr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gitfrok/bff/internal/codereview"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SPEC-0059 AC11–AC13 at the BFF: the form is forwarded under the session, the two
// distinguished outcomes stay distinguished, and the body carries no tracker content.

func serveForm(t *testing.T, s Session, c MergeRequests, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("content-type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	New(c, nil, s).Routes().ServeHTTP(recorder, request)
	return recorder
}

const linkTarget = "/v1/repositories/repo-1/merge_requests/mr-1/external_issues"

func referenced() *codereview.MergeRequest {
	return &codereview.MergeRequest{
		MergeRequestID: "mr-1", RepositoryID: "repo-1", State: "OPEN", Version: 2,
		ExternalIssues: []codereview.ExternalIssue{{
			Tracker: "JIRA", IssueKey: "PLAT-1421",
			URL:      "https://tracker.example.test/browse/PLAT-1421",
			LinkedBy: "dev@x", LinkedAt: "2026-08-19T09:00:00Z",
		}},
	}
}

// AC11: the form's fields travel; the actor does not, because it is the session's.
func TestLinkForwardsTheFormUnderTheSession(t *testing.T) {
	stub := &stubClient{mr: referenced()}
	rec := serveForm(t, session(), stub, linkTarget,
		"tracker=JIRA&issue_key=PLAT-1421&url=https%3A%2F%2Ftracker.example.test%2Fbrowse%2FPLAT-1421&actor_id=someone-else")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if stub.linked.Tracker != "JIRA" || stub.linked.IssueKey != "PLAT-1421" {
		t.Fatalf("forwarded %+v", stub.linked)
	}
	if stub.linked.URL != "https://tracker.example.test/browse/PLAT-1421" {
		t.Errorf("the URL was altered in transit: %q", stub.linked.URL)
	}
	if stub.linkedTo != "mr-1" || stub.linkedRead.RepositoryID != "repo-1" {
		t.Errorf("read context %+v on %q", stub.linkedRead, stub.linkedTo)
	}
	// The form carried an actor. It has nowhere to go: the port takes a reference,
	// and the identity is the session's.
	if stub.linkedRead.ActorID != "actor-a" {
		t.Errorf("the actor came from the request rather than the session: %q", stub.linkedRead.ActorID)
	}
}

func TestUnlinkForwardsTheIdentityOnly(t *testing.T) {
	stub := &stubClient{mr: &codereview.MergeRequest{MergeRequestID: "mr-1", State: "OPEN", Version: 3}}
	rec := serveForm(t, session(), stub, linkTarget+"/unlink", "tracker=JIRA&issue_key=PLAT-1421&url=https%3A%2F%2Fignored.test")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if stub.unlinked.Tracker != "JIRA" || stub.unlinked.IssueKey != "PLAT-1421" {
		t.Fatalf("forwarded %+v", stub.unlinked)
	}
	// Unlink names the reference by identity. A URL on the form is not part of that
	// identity and must not become one.
	if stub.unlinked.URL != "" {
		t.Errorf("the unlink carried a URL: %q", stub.unlinked.URL)
	}
}

// AC12: the two distinguished outcomes, and one coarse refusal for everything else.
func TestTheDistinguishedRefusalsStayDistinguished(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
	}{
		"bad reference": {status.Error(codes.InvalidArgument, "codereview: a reference needs a tracker, an issue key and an https URL"), http.StatusBadRequest},
		"list full":     {status.Error(codes.ResourceExhausted, "codereview: too many"), http.StatusConflict},
		"denied":        {status.Error(codes.PermissionDenied, "merge request unavailable"), http.StatusNotFound},
		"unavailable":   {status.Error(codes.Unavailable, "no backend"), http.StatusNotFound},
	}
	for name, c := range cases {
		rec := serveForm(t, session(), &stubClient{err: c.err}, linkTarget, "tracker=JIRA&issue_key=X&url=https://x.test/1")
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", name, rec.Code, c.want)
		}
	}
}

func TestNoSessionReachesNoReferencePort(t *testing.T) {
	stub := &stubClient{mr: referenced()}
	if rec := serveForm(t, stubSession{}, stub, linkTarget, "tracker=JIRA&issue_key=X&url=https://x.test/1"); rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if stub.linkedTo != "" {
		t.Errorf("the port was reached without a session, for %q", stub.linkedTo)
	}
}

// AC13: the references travel to the browser, and nothing about what the issue says
// travels with them.
func TestTheBodyCarriesTheReferenceAndNoTrackerContent(t *testing.T) {
	rec := serveForm(t, session(), &stubClient{mr: referenced()}, linkTarget,
		"tracker=JIRA&issue_key=PLAT-1421&url=https://tracker.example.test/browse/PLAT-1421")

	var view MRView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(view.ExternalIssues) != 1 || view.ExternalIssues[0].IssueKey != "PLAT-1421" {
		t.Fatalf("unexpected references %+v", view.ExternalIssues)
	}
	// The assertion is scoped to the references, not to the whole body: a merge
	// request legitimately has a title and a state of its own, and a body-wide search
	// would fire on correct code — which is how a check gets deleted rather than fixed.
	references, err := json.Marshal(view.ExternalIssues)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rendered := strings.ToLower(string(references))
	for _, forbidden := range []string{"title", "body", "status", "state", "assignee", "labels", "comments", "attachment", "description"} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("a reference carries %q — this product never asks the tracker: %s", forbidden, references)
		}
	}
}
