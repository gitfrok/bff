package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/handlers"
	"github.com/gitfrok/bff/internal/repositoryregistry"
)

// SPEC-0052 AC8/AC9: the surface shapes and forwards, identity comes only from
// the session, and every failure is one coarse refusal — except the one thing
// that is not a failure at all, an empty list.

type fakeRegistry struct {
	page repositoryregistry.Page
	err  error
	got  aggregate.ReadContext
	tok  string
	size int32
}

func (f *fakeRegistry) List(_ context.Context, read aggregate.ReadContext, pageToken string, pageSize int32) (repositoryregistry.Page, error) {
	f.got, f.tok, f.size = read, pageToken, pageSize
	return f.page, f.err
}

type fakeSession struct {
	read aggregate.ReadContext
	ok   bool
}

func (s fakeSession) ReadContext(*http.Request) (aggregate.ReadContext, bool) { return s.read, s.ok }

func signedIn() fakeSession {
	return fakeSession{read: aggregate.ReadContext{TenantID: "t-1", ActorID: "actor-1", ActorRoles: []string{"member"}}, ok: true}
}

func serve(t *testing.T, reg handlers.Registry, session handlers.Session, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handlers.NewRepositories(reg, session).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestListShapesThePageAndForwardsOnlyTheSession(t *testing.T) {
	reg := &fakeRegistry{page: repositoryregistry.Page{
		Repositories:  []repositoryregistry.Summary{{RepositoryID: "alpha", Name: "Alpha"}},
		NextPageToken: "opaque",
	}}
	rec := serve(t, reg, signedIn(), "/v1/repositories")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var view handlers.RepositoryListView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(view.Repositories) != 1 || view.Repositories[0].RepositoryID != "alpha" {
		t.Fatalf("shaped %+v", view.Repositories)
	}
	if reg.got.TenantID != "t-1" || reg.got.ActorID != "actor-1" {
		t.Fatalf("forwarded %+v", reg.got)
	}
	if reg.got.RequestID == "" {
		t.Fatal("a request id must be minted here, not accepted from the caller")
	}
}

// A list names no repository. Anything a session carried in that field is
// dropped rather than forwarded, so nothing downstream can start honouring it.
func TestListDropsAnyRepositoryTheSessionCarried(t *testing.T) {
	reg := &fakeRegistry{}
	session := signedIn()
	session.read.RepositoryID = "smuggled"
	serve(t, reg, session, "/v1/repositories")
	if reg.got.RepositoryID != "" {
		t.Fatalf("forwarded a repository %q on a surface that names none", reg.got.RepositoryID)
	}
}

// The empty list is a SUCCESS. A caller who may see nothing and a tenant with
// nothing must be indistinguishable, and the marshalled body proves it.
func TestAnEmptyListIsATwoHundredWithAnEmptyArray(t *testing.T) {
	rec := serve(t, &fakeRegistry{page: repositoryregistry.Page{}}, signedIn(), "/v1/repositories")
	if rec.Code != http.StatusOK {
		t.Fatalf("an empty list must not be a refusal, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "{\"repositories\":[],\"next_page_token\":\"\"}\n" {
		t.Fatalf("body %q — the empty page must marshal identically every time", body)
	}
}

func TestARequestWithoutASessionIsRefused(t *testing.T) {
	for name, session := range map[string]fakeSession{
		"no session": {ok: false},
		"no tenant":  {read: aggregate.ReadContext{ActorID: "a"}, ok: true},
		"no actor":   {read: aggregate.ReadContext{TenantID: "t"}, ok: true},
	} {
		rec := serve(t, &fakeRegistry{}, session, "/v1/repositories")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d, want the coarse 404", name, rec.Code)
		}
	}
}

func TestABackendFailureIsTheOneCoarseRefusal(t *testing.T) {
	rec := serve(t, &fakeRegistry{err: errors.New("backend down")}, signedIn(), "/v1/repositories")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
	if body := rec.Body.String(); body != "repositories unavailable\n" {
		t.Fatalf("the refusal names a cause: %q", body)
	}
}

func TestPagingForwardsTheTokenAndBoundsThePageSize(t *testing.T) {
	reg := &fakeRegistry{}
	serve(t, reg, signedIn(), "/v1/repositories?page_token=opaque%3A%3A1&page_size=5")
	if reg.tok != "opaque::1" {
		t.Fatalf("token %q", reg.tok)
	}
	if reg.size != 5 {
		t.Fatalf("size %d", reg.size)
	}

	reg2 := &fakeRegistry{}
	serve(t, reg2, signedIn(), "/v1/repositories?page_size=100000")
	if reg2.size != 200 {
		t.Fatalf("an unbounded page size must be capped, got %d", reg2.size)
	}
}

func TestAMalformedPageSizeIsRefused(t *testing.T) {
	for _, raw := range []string{"abc", "-1"} {
		rec := serve(t, &fakeRegistry{}, signedIn(), "/v1/repositories?page_size="+raw)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("page_size=%s: status %d", raw, rec.Code)
		}
	}
}

func TestTheResponseCarriesNoTotal(t *testing.T) {
	rec := serve(t, &fakeRegistry{page: repositoryregistry.Page{
		Repositories: []repositoryregistry.Summary{{RepositoryID: "alpha", Name: "Alpha"}},
	}}, signedIn(), "/v1/repositories")

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for key := range raw {
		if key != "repositories" && key != "next_page_token" {
			t.Fatalf("the response carries %q — non-enumeration is a property of this shape", key)
		}
	}
}
