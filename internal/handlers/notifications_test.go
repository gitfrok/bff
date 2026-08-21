package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/handlers"
	"github.com/gitfrok/bff/internal/notifications"
)

// The bell surface shapes and forwards. The tests pin the three properties
// that matter: identity comes only from the session, the shaped JSON says
// what happened / where / when / read, and every backend refusal is one
// coarse 404 — never an empty page a reader could misread as "nothing
// happened" (SPEC-0063 AC7).

type stubNotifications struct {
	listCalled bool
	pageSize   int
	pageToken  string
	unread     int64
	markedID   string
	err        error
}

func (s *stubNotifications) List(_ context.Context, _ aggregate.ReadContext, pageSize int, pageToken string) (notifications.Page, error) {
	s.listCalled = true
	s.pageSize, s.pageToken = pageSize, pageToken
	if s.err != nil {
		return notifications.Page{}, s.err
	}
	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	return notifications.Page{
		Notifications: []notifications.Notification{{
			ID: "evt-1:author", Kind: notifications.KindReviewSubmitted,
			RepositoryID: "repo-1", MergeRequestID: "mr-1", ActorID: "reviewer",
			OccurredAt: at, Read: false,
		}},
	}, nil
}

func (s *stubNotifications) UnreadCount(context.Context, aggregate.ReadContext) (int64, error) {
	return s.unread, s.err
}

func (s *stubNotifications) MarkRead(_ context.Context, _ aggregate.ReadContext, id string) (*notifications.Notification, error) {
	s.markedID = id
	if s.err != nil {
		return nil, s.err
	}
	read := true
	return &notifications.Notification{ID: id, Kind: notifications.KindReviewSubmitted, Read: read}, nil
}

type stubSession struct{ read aggregate.ReadContext }

func (s stubSession) ReadContext(*http.Request) (aggregate.ReadContext, bool) {
	return s.read, true
}

func request(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	return r
}

func TestListShapesWhatHappenedWhereWhen(t *testing.T) {
	stub := &stubNotifications{}
	h := handlers.NewNotifications(stub, stubSession{read: aggregate.ReadContext{
		TenantID: "t1", ActorID: "author",
	}})
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, request("GET", "/v1/notifications?page_size=10&page_token=abc"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if !stub.listCalled || stub.pageSize != 10 || stub.pageToken != "abc" {
		t.Fatalf("forwarded pageSize=%d token=%q called=%v", stub.pageSize, stub.pageToken, stub.listCalled)
	}
	var view struct {
		Notifications []struct {
			ID           string `json:"id"`
			Kind         string `json:"kind"`
			RepositoryID string `json:"repository_id"`
			OccurredAt   string `json:"occurred_at"`
			Read         bool   `json:"read"`
		} `json:"notifications"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Notifications) != 1 {
		t.Fatalf("rows = %+v, want one", view.Notifications)
	}
	row := view.Notifications[0]
	if row.ID != "evt-1:author" || row.Kind != "REVIEW_SUBMITTED" || row.RepositoryID != "repo-1" || row.Read {
		t.Fatalf("shaped row = %+v", row)
	}
	if row.OccurredAt != "2026-08-21T12:00:00Z" {
		t.Fatalf("occurred_at = %q, want the RFC3339 instant the event carried", row.OccurredAt)
	}
}

func TestUnreadCountZeroIsZero(t *testing.T) {
	stub := &stubNotifications{}
	h := handlers.NewNotifications(stub, stubSession{read: aggregate.ReadContext{
		TenantID: "t1", ActorID: "author",
	}})
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, request("GET", "/v1/notifications/unread_count"))
	if rec.Code != http.StatusOK || rec.Body.String() != "{\"unread\":0}\n" {
		t.Fatalf("body = %q, status = %d; zero must marshal as zero", rec.Body, rec.Code)
	}
}

func TestMarkReadForwardsThePathIdentity(t *testing.T) {
	stub := &stubNotifications{}
	h := handlers.NewNotifications(stub, stubSession{read: aggregate.ReadContext{
		TenantID: "t1", ActorID: "author",
	}})
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, request("POST", "/v1/notifications/evt-9%3Aauthor/mark_read"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	if stub.markedID != "evt-9:author" {
		t.Fatalf("marked %q, want the path's opaque ID decoded once", stub.markedID)
	}
	var view struct {
		Read bool `json:"read"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if !view.Read {
		t.Fatal("marked row marshals as unread")
	}
}

// A dead session is refused before anything reaches the client.
func TestDeadSessionRefusedCoarsely(t *testing.T) {
	stub := &stubNotifications{}
	h := handlers.NewNotifications(stub, failingSession{})
	for _, tc := range []struct{ method, target string }{
		{"GET", "/v1/notifications"},
		{"GET", "/v1/notifications/unread_count"},
		{"POST", "/v1/notifications/x/mark_read"},
	} {
		rec := httptest.NewRecorder()
		h.Routes().ServeHTTP(rec, request(tc.method, tc.target))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s = %d, want 404", tc.method, tc.target, rec.Code)
		}
	}
	if stub.listCalled || stub.markedID != "" {
		t.Fatal("a refused session reached the backend")
	}
}

func TestBackendFailureIsOneCoarse404NotAnEmptyPage(t *testing.T) {
	stub := &stubNotifications{err: errors.New("backend down")}
	h := handlers.NewNotifications(stub, stubSession{read: aggregate.ReadContext{
		TenantID: "t1", ActorID: "author",
	}})
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, request("GET", "/v1/notifications"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if rec.Header().Get("Content-Type") == "application/json" && rec.Body.String() == "{\"notifications\":[]}" {
		t.Fatal("a failed read rendered as an empty page")
	}
}

type failingSession struct{}

func (failingSession) ReadContext(*http.Request) (aggregate.ReadContext, bool) {
	return aggregate.ReadContext{}, false
}
