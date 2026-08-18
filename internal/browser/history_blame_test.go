package browser_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/browser"
)

// SPEC-0053 AC8/AC9 at the BFF: the surface shapes and forwards, every failure
// is one coarse refusal, and — the point of this surface — git identity keeps
// its git_ names all the way to the browser.

type historyReader struct {
	page    aggregate.HistoryPage
	blame   aggregate.BlameResult
	err     error
	gotRev  string
	gotPath string
	gotTok  string
}

func (r *historyReader) Tree(context.Context, aggregate.ReadContext, string, string, int) (aggregate.TreePage, error) {
	return aggregate.TreePage{}, errors.New("not this route")
}
func (r *historyReader) File(context.Context, aggregate.ReadContext, string, string, func(aggregate.FileChunk) error) error {
	return errors.New("not this route")
}
func (r *historyReader) Diff(context.Context, aggregate.ReadContext, string, string, string, func(aggregate.DiffChunk) error) error {
	return errors.New("not this route")
}
func (r *historyReader) History(_ context.Context, _ aggregate.ReadContext, revision, path, pageToken string, _ int32) (aggregate.HistoryPage, error) {
	r.gotRev, r.gotPath, r.gotTok = revision, path, pageToken
	return r.page, r.err
}
func (r *historyReader) Blame(_ context.Context, _ aggregate.ReadContext, revision, path string) (aggregate.BlameResult, error) {
	r.gotRev, r.gotPath = revision, path
	return r.blame, r.err
}

type okSession struct{ ok bool }

func (s okSession) ReadContext(*http.Request) (aggregate.ReadContext, bool) {
	if !s.ok {
		return aggregate.ReadContext{}, false
	}
	return aggregate.ReadContext{TenantID: "t-1", ActorID: "a-1", RequestID: "r-1"}, true
}

func call(t *testing.T, reader browser.Reader, session browser.Session, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	browser.New(reader, session).Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func identity() aggregate.CommitIdentity {
	return aggregate.CommitIdentity{
		GitAuthorName: "Ada", GitAuthorEmail: "ada@example.test",
		GitCommitterName: "Grace", GitCommitterEmail: "grace@example.test",
		AuthoredAt: "2026-08-19T00:00:00Z", CommittedAt: "2026-08-19T01:00:00Z",
	}
}

func TestHistoryShapesTheCommitsAndForwardsTheQuery(t *testing.T) {
	reader := &historyReader{page: aggregate.HistoryPage{
		Commits:       []aggregate.Commit{{CommitID: "abc123", Identity: identity(), Subject: "Add the thing"}},
		NextPageToken: "opaque",
	}}
	rec := call(t, reader, okSession{ok: true}, "/v1/repositories/repo-1/history?revision=main&path=a.go&page_token=tok")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if reader.gotRev != "main" || reader.gotPath != "a.go" || reader.gotTok != "tok" {
		t.Fatalf("forwarded rev=%q path=%q tok=%q", reader.gotRev, reader.gotPath, reader.gotTok)
	}
	var view browser.HistoryView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Commits[0].Identity.GitAuthorName != "Ada" {
		t.Fatalf("shaped %+v", view.Commits[0].Identity)
	}
}

// AC8's whole point, asserted on the wire the browser actually reads: the JSON
// keys say git_. A key called "author" would let the layer above render an
// unverified string as an account.
func TestTheJSONNamesGitIdentityAsGitIdentity(t *testing.T) {
	reader := &historyReader{page: aggregate.HistoryPage{
		Commits: []aggregate.Commit{{CommitID: "abc123", Identity: identity(), Subject: "s"}},
	}}
	body := call(t, reader, okSession{ok: true}, "/v1/repositories/repo-1/history?revision=main").Body.String()

	for _, key := range []string{"git_author_name", "git_author_email", "git_committer_name", "git_committer_email"} {
		if !strings.Contains(body, key) {
			t.Fatalf("the response omits %q: %s", key, body)
		}
	}
	for _, forbidden := range []string{`"author"`, `"actor_id"`, `"principal_id"`, `"user"`, `"account"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("the response carries %s — a platform identity this layer never verified", forbidden)
		}
	}
}

func TestBlameCarriesTheCappedFlag(t *testing.T) {
	reader := &historyReader{blame: aggregate.BlameResult{
		Ranges: []aggregate.BlameRange{{StartLine: 1, EndLine: 12, CommitID: "abc", Identity: identity()}},
		Capped: true,
	}}
	rec := call(t, reader, okSession{ok: true}, "/v1/repositories/repo-1/blame?revision=main&path=a.go")

	var view browser.BlameView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !view.Capped {
		t.Fatal("capped did not survive to the browser — a partial attribution would read as whole")
	}
	if view.Ranges[0].EndLine != 12 {
		t.Fatalf("shaped %+v", view.Ranges[0])
	}
}

func TestAnUncappedBlameSaysSo(t *testing.T) {
	reader := &historyReader{blame: aggregate.BlameResult{Ranges: []aggregate.BlameRange{{StartLine: 1, EndLine: 2}}}}
	rec := call(t, reader, okSession{ok: true}, "/v1/repositories/repo-1/blame?revision=main&path=a.go")
	var view browser.BlameView
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view.Capped {
		t.Fatal("an uncapped blame reported itself capped")
	}
}

func TestBothRoutesRefuseWithoutASession(t *testing.T) {
	for _, target := range []string{
		"/v1/repositories/repo-1/history?revision=main",
		"/v1/repositories/repo-1/blame?revision=main&path=a.go",
	} {
		rec := call(t, &historyReader{}, okSession{ok: false}, target)
		if rec.Code == http.StatusOK {
			t.Fatalf("%s served without a session", target)
		}
	}
}

func TestABackendFailureIsOneCoarseRefusal(t *testing.T) {
	for _, target := range []string{
		"/v1/repositories/repo-1/history?revision=main",
		"/v1/repositories/repo-1/blame?revision=main&path=a.go",
	} {
		rec := call(t, &historyReader{err: errors.New("backend down")}, okSession{ok: true}, target)
		if rec.Code == http.StatusOK {
			t.Fatalf("%s served on a backend failure", target)
		}
		if strings.Contains(strings.ToLower(rec.Body.String()), "backend down") {
			t.Fatalf("%s leaked the cause: %s", target, rec.Body.String())
		}
	}
}
