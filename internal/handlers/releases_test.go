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
	"github.com/gitfrok/bff/internal/releases"
)

// SPEC-0056 AC9/AC10 at the BFF: shapes and forwards, one coarse refusal, and
// no artifact anywhere on the surface.

type fakeReleases struct {
	tags     []releases.Tag
	list     []releases.Release
	record   releases.Release
	err      error
	gotRead  aggregate.ReadContext
	gotTag   string
	gotNotes string
}

func (f *fakeReleases) Tags(_ context.Context, read aggregate.ReadContext, _ string, _ int32) ([]releases.Tag, string, error) {
	f.gotRead = read
	return f.tags, "", f.err
}
func (f *fakeReleases) Publish(_ context.Context, read aggregate.ReadContext, tag, notes string) (releases.Release, error) {
	f.gotRead, f.gotTag, f.gotNotes = read, tag, notes
	return f.record, f.err
}
func (f *fakeReleases) Get(_ context.Context, read aggregate.ReadContext, tag string) (releases.Release, error) {
	f.gotRead, f.gotTag = read, tag
	return f.record, f.err
}
func (f *fakeReleases) List(_ context.Context, read aggregate.ReadContext, _ string, _ int32) ([]releases.Release, string, error) {
	f.gotRead = read
	return f.list, "", f.err
}
func (f *fakeReleases) UpdateNotes(_ context.Context, read aggregate.ReadContext, tag, notes string) (releases.Release, error) {
	f.gotRead, f.gotTag, f.gotNotes = read, tag, notes
	return f.record, f.err
}

func relSession() fakeSession {
	return fakeSession{read: aggregate.ReadContext{TenantID: "t-1", ActorID: "dev@x"}, ok: true}
}

func serveRel(t *testing.T, r handlers.Releases, session handlers.Session, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("content-type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	handlers.NewReleases(r, session).ServeHTTP(rec, req)
	return rec
}

func TestPublishForwardsTheTagAndNotesFormEncoded(t *testing.T) {
	fake := &fakeReleases{record: releases.Release{
		Tag: "v1.0.0", PublishedCommit: "abc123", Notes: "what changed",
		PublishedBy: "dev@x", PublishedAt: "2026-08-19T09:00:00Z",
	}}
	rec := serveRel(t, fake, relSession(), http.MethodPost, "/v1/repositories/repo-1/releases",
		"tag=v1.0.0&notes=what+changed")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if fake.gotTag != "v1.0.0" || fake.gotNotes != "what changed" {
		t.Fatalf("forwarded tag=%q notes=%q", fake.gotTag, fake.gotNotes)
	}
	if fake.gotRead.RepositoryID != "repo-1" || fake.gotRead.RequestID == "" {
		t.Fatalf("read context %+v", fake.gotRead)
	}
}

// The one distinguished outcome: a conflict with a state the caller can see.
func TestASecondReleaseOfTheSameTagIsAConflictNotTheCoarseRefusal(t *testing.T) {
	rec := serveRel(t, &fakeReleases{err: releases.ErrAlreadyPublished}, relSession(),
		http.MethodPost, "/v1/repositories/repo-1/releases", "tag=v1.0.0")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", rec.Code)
	}
}

func TestEveryOtherFailureIsOneCoarseRefusal(t *testing.T) {
	for name, target := range map[string]string{
		"tags": "/v1/repositories/repo-1/tags",
		"list": "/v1/repositories/repo-1/releases",
		"get":  "/v1/repositories/repo-1/releases/v1.0.0",
	} {
		rec := serveRel(t, &fakeReleases{err: errors.New("backend down")}, relSession(), http.MethodGet, target, "")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d", name, rec.Code)
		}
		if body := rec.Body.String(); body != "releases unavailable\n" {
			t.Fatalf("%s: the refusal names a cause: %q", name, body)
		}
	}
}

// AC9 at the layer the browser reads: nothing on this surface carries or
// gestures at an artifact.
func TestNothingOnThisSurfaceCarriesAnArtifact(t *testing.T) {
	fake := &fakeReleases{list: []releases.Release{{
		Tag: "v1.0.0", PublishedCommit: "abc", Notes: "x", PublishedBy: "d", PublishedAt: "t",
	}}}
	body := serveRel(t, fake, relSession(), http.MethodGet, "/v1/repositories/repo-1/releases", "").Body.String()
	for _, forbidden := range []string{"artifact", "asset", "download", "attachment", "upload"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("the response mentions %q — artifacts are outside ADR-0075's increment: %s", forbidden, body)
		}
	}
}

// The record and the tag list both travel, because the reader compares them.
func TestTheRecordedCommitAndTheCurrentTagBothTravel(t *testing.T) {
	fake := &fakeReleases{
		record: releases.Release{Tag: "v1.0.0", PublishedCommit: "then111"},
		tags:   []releases.Tag{{Name: "v1.0.0", CommitID: "now999"}},
	}
	var release handlers.ReleaseView
	relBody := serveRel(t, fake, relSession(), http.MethodGet, "/v1/repositories/repo-1/releases/v1.0.0", "").Body.Bytes()
	if err := json.Unmarshal(relBody, &release); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var tags handlers.TagListView
	tagBody := serveRel(t, fake, relSession(), http.MethodGet, "/v1/repositories/repo-1/tags", "").Body.Bytes()
	if err := json.Unmarshal(tagBody, &tags); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Neither layer decides they have diverged; both facts reach the reader.
	if release.PublishedCommit != "then111" || tags.Tags[0].CommitID != "now999" {
		t.Fatalf("release=%+v tags=%+v", release, tags)
	}
}

func TestAnEmptyReleaseListIsASuccess(t *testing.T) {
	rec := serveRel(t, &fakeReleases{}, relSession(), http.MethodGet, "/v1/repositories/repo-1/releases", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if body := rec.Body.String(); body != "{\"releases\":[],\"next_page_token\":\"\"}\n" {
		t.Fatalf("body %q", body)
	}
}

func TestReleasesRefuseWithoutASession(t *testing.T) {
	rec := serveRel(t, &fakeReleases{}, fakeSession{ok: false}, http.MethodGet, "/v1/repositories/repo-1/releases", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestNotesCanBeCorrectedAndTheTagCannotBeMoved(t *testing.T) {
	fake := &fakeReleases{record: releases.Release{Tag: "v1.0.0", PublishedCommit: "abc", Notes: "fixed"}}
	rec := serveRel(t, fake, relSession(), http.MethodPost,
		"/v1/repositories/repo-1/releases/v1.0.0/notes", "notes=fixed&published_commit=hijacked&tag=v9")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	// The tag comes from the path and the commit is never read from a form:
	// there is no parameter by which a note edit could move a release.
	if fake.gotTag != "v1.0.0" || fake.gotNotes != "fixed" {
		t.Fatalf("forwarded tag=%q notes=%q", fake.gotTag, fake.gotNotes)
	}
}
