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
	"github.com/gitfrok/bff/internal/fleet"
	"github.com/gitfrok/bff/internal/handlers"
)

// SPEC-0058 AC9–AC11 at the BFF: shapes and forwards under the session, one coarse
// refusal that covers an unconfigured door, and no audit or per-person vocabulary.

type fakeFleet struct {
	planes  []fleet.Plane
	err     error
	gotRead aggregate.ReadContext
	calls   int
}

func (f *fakeFleet) List(_ context.Context, read aggregate.ReadContext) ([]fleet.Plane, error) {
	f.gotRead = read
	f.calls++
	return f.planes, f.err
}

func fleetSession() fakeSession {
	return fakeSession{read: aggregate.ReadContext{TenantID: "t-1", ActorID: "owner@x", ActorRoles: []string{"owner"}}, ok: true}
}

func serveFleet(t *testing.T, f handlers.Fleet, session handlers.Session) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/fleet", nil)
	rec := httptest.NewRecorder()
	handlers.NewFleet(f, session).ServeHTTP(rec, req)
	return rec
}

func TestFleetForwardsTheSessionsContext(t *testing.T) {
	fake := &fakeFleet{planes: []fleet.Plane{{
		DataPlaneID: "dp-1", Status: "CONNECTED", Cloud: "CLOUD_GKE", Region: "eu-west-1",
		AgentVersion: "1.4.0", K8sVersion: "1.30", LastSeenAt: "2026-08-19T09:00:00Z",
	}}}
	rec := serveFleet(t, fake, fleetSession())

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if fake.gotRead.TenantID != "t-1" || fake.gotRead.ActorID != "owner@x" || fake.gotRead.RequestID == "" {
		t.Fatalf("read context %+v", fake.gotRead)
	}
	var got handlers.FleetView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(got.Planes) != 1 || got.Planes[0].DataPlaneID != "dp-1" || got.Planes[0].Status != "CONNECTED" {
		t.Fatalf("unexpected view %+v", got.Planes)
	}
	if got.Planes[0].LastSeenAt != "2026-08-19T09:00:00Z" {
		t.Errorf("the age must travel: %q", got.Planes[0].LastSeenAt)
	}
}

// AC10: an unconfigured door is unavailable, NOT an empty fleet. A 200 with no
// planes would tell an administrator their tenant has no data planes when what is
// actually known is that nothing was asked.
func TestAnUnconfiguredDoorIsUnavailableRatherThanEmpty(t *testing.T) {
	rec := serveFleet(t, &fakeFleet{err: fleet.ErrUnavailable}, fleetSession())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "fleet report unavailable") {
		t.Errorf("unexpected refusal %q", body)
	}
}

// A tenant that genuinely has no data planes is a successful, empty answer — the
// other side of AC10's distinction.
func TestATenantWithNoPlanesIsASuccessfulEmptyAnswer(t *testing.T) {
	rec := serveFleet(t, &fakeFleet{}, fleetSession())
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	var got handlers.FleetView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(got.Planes) != 0 {
		t.Errorf("want no planes, got %d", len(got.Planes))
	}
}

func TestEveryFleetFailureIsOneCoarseRefusal(t *testing.T) {
	for name, err := range map[string]error{
		"unavailable": fleet.ErrUnavailable,
		"unknown":     errors.New("the control plane fell over"),
	} {
		rec := serveFleet(t, &fakeFleet{err: err}, fleetSession())
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", name, rec.Code)
		}
	}
}

func TestNoSessionReachesNoFleetPort(t *testing.T) {
	fake := &fakeFleet{}
	if rec := serveFleet(t, fake, fakeSession{}); rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if fake.calls != 0 {
		t.Errorf("the port was reached %d times without a session", fake.calls)
	}
}

// AC11: the body carries no audit-record, member or activity vocabulary. Decision
// 1's boundary at the layer a browser reads.
func TestTheFleetBodyCarriesNoAuditOrPersonVocabulary(t *testing.T) {
	fake := &fakeFleet{planes: []fleet.Plane{{
		DataPlaneID: "dp-1", Status: "STALE", LastSeenAt: "2026-08-15T09:00:00Z",
	}}}
	body := strings.ToLower(serveFleet(t, fake, fleetSession()).Body.String())
	for _, forbidden := range []string{"audit", "trail", "record", "member", "last_active", "user", "email"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the fleet body carries %q — outside ADR-0077's accepted increment: %s", forbidden, body)
		}
	}
}

// A stale plane arrives stale and leaves stale. This layer does not decide that a
// plane which stopped answering is probably fine.
func TestAStalePlaneIsForwardedAsStale(t *testing.T) {
	fake := &fakeFleet{planes: []fleet.Plane{{DataPlaneID: "dp-2", Status: "STALE", LastSeenAt: "2026-08-10T09:00:00Z"}}}
	var got handlers.FleetView
	if err := json.Unmarshal(serveFleet(t, fake, fleetSession()).Body.Bytes(), &got); err != nil {
		t.Fatalf("body: %v", err)
	}
	if got.Planes[0].Status != "STALE" {
		t.Errorf("want STALE, got %q", got.Planes[0].Status)
	}
}

// A never-connected row keeps its token and claims no contact.
func TestANeverConnectedRowClaimsNoContact(t *testing.T) {
	fake := &fakeFleet{planes: []fleet.Plane{{Status: "NEVER_CONNECTED", TokenID: "tok-9"}}}
	var got handlers.FleetView
	if err := json.Unmarshal(serveFleet(t, fake, fleetSession()).Body.Bytes(), &got); err != nil {
		t.Fatalf("body: %v", err)
	}
	if got.Planes[0].TokenID != "tok-9" || got.Planes[0].LastSeenAt != "" {
		t.Errorf("unexpected row %+v", got.Planes[0])
	}
}
