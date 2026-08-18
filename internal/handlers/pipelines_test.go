package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/handlers"
	"github.com/gitfrok/bff/internal/pipelines"
)

// SPEC-0054 AC8/AC9 at the BFF, plus the property ADR-0072 turns on: nothing
// on this surface carries or gestures at job output.

type fakeRuns struct {
	page pipelines.Page
	err  error
	got  aggregate.ReadContext
	repo string
	tok  string
	size int32
}

func (f *fakeRuns) List(_ context.Context, read aggregate.ReadContext, repositoryID, pageToken string, pageSize int32) (pipelines.Page, error) {
	f.got, f.repo, f.tok, f.size = read, repositoryID, pageToken, pageSize
	return f.page, f.err
}

func runSession() fakeSession {
	return fakeSession{read: aggregate.ReadContext{TenantID: "t-1", ActorID: "a-1", ActorRoles: []string{"member"}}, ok: true}
}

func serveRuns(t *testing.T, runs handlers.Runs, session handlers.Session, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handlers.NewPipelines(runs, session).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestRunsAreShapedAndTheSessionIsForwarded(t *testing.T) {
	runs := &fakeRuns{page: pipelines.Page{
		Runs: []pipelines.Run{{
			JobID: "job-1", RepositoryID: "repo-1", Ref: "refs/heads/main",
			CommitSHA: "abc123", Trigger: "JOB_TRIGGER_KIND_REF_UPDATED",
			State: "JOB_STATE_SUCCEEDED", QueuedAt: "2026-08-19T09:00:00Z",
			OutcomeSummary: "all green",
		}},
		NextPageToken: "opaque",
	}}
	rec := serveRuns(t, runs, runSession(), "/api/v1/pipelines/runs?repository_id=repo-1&page_size=5")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var view handlers.RunListView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(view.Runs) != 1 || view.Runs[0].JobID != "job-1" {
		t.Fatalf("shaped %+v", view.Runs)
	}
	if runs.got.TenantID != "t-1" || runs.got.RequestID == "" {
		t.Fatalf("forwarded %+v", runs.got)
	}
	if runs.repo != "repo-1" || runs.size != 5 {
		t.Fatalf("repo=%q size=%d", runs.repo, runs.size)
	}
}

// ADR-0072's deferral, asserted on the wire the browser reads: no field here
// carries or gestures at job output, and none links to it.
func TestNothingOnThisSurfaceCarriesOrGesturesAtJobOutput(t *testing.T) {
	runs := &fakeRuns{page: pipelines.Page{Runs: []pipelines.Run{{JobID: "job-1", State: "JOB_STATE_FAILED"}}}}
	body := serveRuns(t, runs, runSession(), "/api/v1/pipelines/runs").Body.String()

	for _, forbidden := range []string{"log", "output", "stdout", "stderr", "console", "artifact"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("the response mentions %q — job output is ADR-0072's deferred decision: %s", forbidden, body)
		}
	}
}

// The empty page is a success and marshals identically every time.
func TestAnEmptyRunListIsATwoHundredWithAnEmptyArray(t *testing.T) {
	rec := serveRuns(t, &fakeRuns{page: pipelines.Page{}}, runSession(), "/api/v1/pipelines/runs")
	if rec.Code != http.StatusOK {
		t.Fatalf("an empty list must not be a refusal, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "{\"runs\":[],\"next_page_token\":\"\"}\n" {
		t.Fatalf("body %q", body)
	}
}

func TestRunsRefuseWithoutASession(t *testing.T) {
	for name, session := range map[string]fakeSession{
		"no session": {ok: false},
		"no tenant":  {read: aggregate.ReadContext{ActorID: "a"}, ok: true},
	} {
		if rec := serveRuns(t, &fakeRuns{}, session, "/api/v1/pipelines/runs"); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d", name, rec.Code)
		}
	}
}

func TestARunsBackendFailureIsOneCoarseRefusal(t *testing.T) {
	rec := serveRuns(t, &fakeRuns{err: errors.New("ci down")}, runSession(), "/api/v1/pipelines/runs")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
	if body := rec.Body.String(); body != "pipelines unavailable\n" {
		t.Fatalf("the refusal names a cause: %q", body)
	}
}

func TestThePageSizeIsBoundedAndAMalformedOneIsRefused(t *testing.T) {
	runs := &fakeRuns{}
	serveRuns(t, runs, runSession(), "/api/v1/pipelines/runs?page_size=100000")
	if runs.size != 200 {
		t.Fatalf("unbounded page size not capped: %d", runs.size)
	}
	for _, raw := range []string{"abc", "-1"} {
		if rec := serveRuns(t, &fakeRuns{}, runSession(), "/api/v1/pipelines/runs?page_size="+raw); rec.Code != http.StatusNotFound {
			t.Fatalf("page_size=%s: status %d", raw, rec.Code)
		}
	}
}

func TestTheRunListCarriesNoTotal(t *testing.T) {
	rec := serveRuns(t, &fakeRuns{page: pipelines.Page{Runs: []pipelines.Run{{JobID: "j"}}}}, runSession(), "/api/v1/pipelines/runs")
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for key := range raw {
		if key != "runs" && key != "next_page_token" {
			t.Fatalf("the response carries %q", key)
		}
	}
}
