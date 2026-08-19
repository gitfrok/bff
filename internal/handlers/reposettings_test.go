package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/handlers"
	"github.com/gitfrok/bff/internal/reposettings"
)

// SPEC-0057 AC13/AC14 at the BFF: shapes and forwards under the session, one coarse refusal, and no
// visibility, membership or policy vocabulary anywhere on the surface.

type fakeRepoSettings struct {
	settings    reposettings.Settings
	err         error
	gotRead     aggregate.ReadContext
	gotName     string
	gotDesc     string
	gotArchived bool
	archived    int
}

func (f *fakeRepoSettings) Get(_ context.Context, read aggregate.ReadContext) (reposettings.Settings, error) {
	f.gotRead = read
	return f.settings, f.err
}

func (f *fakeRepoSettings) Update(_ context.Context, read aggregate.ReadContext, name, description string) (reposettings.Settings, error) {
	f.gotRead, f.gotName, f.gotDesc = read, name, description
	return f.settings, f.err
}

func (f *fakeRepoSettings) SetArchived(_ context.Context, read aggregate.ReadContext, archived bool) (reposettings.Settings, error) {
	f.gotRead, f.gotArchived = read, archived
	f.archived++
	return f.settings, f.err
}

func settingsSession() fakeSession {
	return fakeSession{read: aggregate.ReadContext{TenantID: "t-1", ActorID: "owner@x"}, ok: true}
}

func serveSettings(t *testing.T, s handlers.RepoSettings, session handlers.Session, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("content-type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	handlers.NewRepoSettings(s, session).ServeHTTP(rec, req)
	return rec
}

func TestSettingsReadForwardsTheSessionsContext(t *testing.T) {
	fake := &fakeRepoSettings{settings: reposettings.Settings{
		RepositoryID: "repo-1", Name: "infra", Description: "the cluster",
		SettingsUpdatedAt: "2026-08-19T09:30:00Z", SettingsUpdatedBy: "owner@x",
	}}
	rec := serveSettings(t, fake, settingsSession(), http.MethodGet, "/v1/repositories/repo-1/settings", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if fake.gotRead.RepositoryID != "repo-1" || fake.gotRead.TenantID != "t-1" || fake.gotRead.RequestID == "" {
		t.Fatalf("read context %+v", fake.gotRead)
	}
	var got handlers.SettingsView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body: %v", err)
	}
	if got.Name != "infra" || got.Description != "the cluster" || got.SettingsUpdatedBy != "owner@x" {
		t.Errorf("unexpected view %+v", got)
	}
	if got.ArchivedAt != "" {
		t.Errorf("an unarchived repository claims an instant: %q", got.ArchivedAt)
	}
}

// AC13: the write is form-encoded, and the actor never travels as a field — it is the session's.
func TestSettingsUpdateForwardsTheFormAndNotTheActor(t *testing.T) {
	fake := &fakeRepoSettings{settings: reposettings.Settings{RepositoryID: "repo-1", Name: "platform"}}
	rec := serveSettings(t, fake, settingsSession(), http.MethodPost, "/v1/repositories/repo-1/settings",
		"name=platform&description=the+cluster&actor_id=someone-else&visibility=public")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if fake.gotName != "platform" || fake.gotDesc != "the cluster" {
		t.Fatalf("forwarded name=%q description=%q", fake.gotName, fake.gotDesc)
	}
	// The form carried an actor and a visibility. Neither has anywhere to go: the port takes a
	// name and a description, and the actor comes from the session.
	if fake.gotRead.ActorID != "owner@x" {
		t.Errorf("the actor came from the request rather than the session: %q", fake.gotRead.ActorID)
	}
}

// AC13: the one distinguished outcome is the empty name — about a field the caller already sent.
func TestARenameToNothingIsABadRequestNotTheCoarseRefusal(t *testing.T) {
	rec := serveSettings(t, &fakeRepoSettings{err: reposettings.ErrNameRequired}, settingsSession(),
		http.MethodPost, "/v1/repositories/repo-1/settings", "name=")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

// AC13/AC5: everything else is one refusal that names no cause.
func TestEverySettingsFailureIsOneCoarseRefusal(t *testing.T) {
	for name, target := range map[string]string{
		"read":    "/v1/repositories/repo-1/settings",
		"archive": "/v1/repositories/repo-1/settings/archive",
	} {
		method := http.MethodGet
		body := ""
		if name == "archive" {
			method, body = http.MethodPost, "archived=true"
		}
		rec := serveSettings(t, &fakeRepoSettings{err: reposettings.ErrUnavailable}, settingsSession(), method, target, body)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", name, rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, "repository settings unavailable") {
			t.Errorf("%s: unexpected refusal %q", name, body)
		}
	}
}

// A caller with no session reaches nothing.
func TestNoSessionReachesNoSettingsPort(t *testing.T) {
	fake := &fakeRepoSettings{}
	rec := serveSettings(t, fake, fakeSession{}, http.MethodPost, "/v1/repositories/repo-1/settings/archive", "archived=true")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if fake.archived != 0 {
		t.Errorf("the port was reached %d times without a session", fake.archived)
	}
}

// AC3 at this layer: the form states the state wanted, so a resubmitted form is not a toggle. A
// toggle route would make a double-submit flip the state, and a person cannot tell a slow response
// from a lost one.
func TestArchiveStatesTheStateWantedRatherThanToggling(t *testing.T) {
	fake := &fakeRepoSettings{settings: reposettings.Settings{RepositoryID: "repo-1", Name: "infra", ArchivedAt: "2026-08-19T09:30:00Z"}}

	for i := 0; i < 2; i++ {
		if rec := serveSettings(t, fake, settingsSession(), http.MethodPost,
			"/v1/repositories/repo-1/settings/archive", "archived=true"); rec.Code != http.StatusOK {
			t.Fatalf("submit %d: status %d", i, rec.Code)
		}
		if !fake.gotArchived {
			t.Fatalf("submit %d asked for the wrong state", i)
		}
	}
}

// AC14: the response body carries no visibility, membership or policy vocabulary. The contract's
// check 16 asserts the same absence in governance; this asserts it at the layer a browser reads, so
// a helpfully-added field here fails too.
func TestTheSettingsBodyCarriesNoExcludedVocabulary(t *testing.T) {
	fake := &fakeRepoSettings{settings: reposettings.Settings{
		RepositoryID: "repo-1", Name: "infra", Description: "the cluster",
		ArchivedAt: "2026-08-19T09:30:00Z", SettingsUpdatedAt: "2026-08-19T09:30:00Z", SettingsUpdatedBy: "owner@x",
	}}
	rec := serveSettings(t, fake, settingsSession(), http.MethodGet, "/v1/repositories/repo-1/settings", "")

	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{
		"visibility", "public", "private", "member", "role",
		"branch_protection", "protected", "required_approvals", "approval", "merge_rule",
		"permission", "delete",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the settings body carries %q — outside ADR-0076's accepted increment: %s", forbidden, rec.Body.String())
		}
	}
}

// AC12 at this layer: there is no delete route, and no route that would remove a repository. A door
// that exists and refuses is a promise nobody has made.
func TestThereIsNoDeleteRoute(t *testing.T) {
	fake := &fakeRepoSettings{}
	for _, target := range []string{
		"/v1/repositories/repo-1/settings/delete",
		"/v1/repositories/repo-1/settings/visibility",
		"/v1/repositories/repo-1/settings/members",
	} {
		rec := serveSettings(t, fake, settingsSession(), http.MethodPost, target, "")
		if rec.Code == http.StatusOK {
			t.Errorf("%s answered 200 — it must not exist", target)
		}
	}
	for _, target := range []string{"/v1/repositories/repo-1/settings"} {
		rec := serveSettings(t, fake, settingsSession(), http.MethodDelete, target, "")
		if rec.Code == http.StatusOK {
			t.Errorf("DELETE %s answered 200 — deletion is ADR-0076's deferred decision", target)
		}
	}
}
