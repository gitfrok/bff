package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/audit"
)

// stubEvidence records the identity and requests it was handed and answers
// with canned pack shapes.
type stubEvidence struct {
	read    aggregate.ReadContext
	request audit.PackRequest
	status  audit.PackStatus
	packID  string
	ref     audit.PackReference
	chunks  []audit.Chunk
	err     error
	calls   int
}

func (s *stubEvidence) RequestPack(_ context.Context, read aggregate.ReadContext, in audit.PackRequest) (audit.PackReference, error) {
	s.read, s.request, s.calls = read, in, s.calls+1
	return s.ref, s.err
}

func (s *stubEvidence) PackStatus(_ context.Context, read aggregate.ReadContext, packID string) (audit.PackStatus, error) {
	s.read, s.packID, s.calls = read, packID, s.calls+1
	return s.status, s.err
}

func (s *stubEvidence) GetPack(_ context.Context, read aggregate.ReadContext, packID string, send func(audit.Chunk) error) error {
	s.read, s.packID, s.calls = read, packID, s.calls+1
	if s.err != nil {
		return s.err
	}
	for _, chunk := range s.chunks {
		if err := send(chunk); err != nil {
			return err
		}
	}
	return nil
}

func serveEvidence(t *testing.T, h *EvidenceHandler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	h.Routes().ServeHTTP(recorder, httptest.NewRequest(method, target, strings.NewReader(body)))
	return recorder
}

const packBody = `{"range_from":"2026-07-01T00:00:00Z","range_to":"2026-07-31T23:59:59Z","repository_id":"repo-a"}`

// A pack request is forwarded under the session's verified identity with
// only the closed range and repository scope, and answered with the pack
// identity now assembling (SPEC-0032 AC4).
func TestRequestPackShapesReference(t *testing.T) {
	ev := &stubEvidence{ref: audit.PackReference{PackID: "pack-1", State: audit.PackPending}}
	response := serveEvidence(t, NewEvidence(ev, session()), http.MethodPost, "/api/v1/audit/evidence-packs", packBody)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, want := range []string{`"pack_id":"pack-1"`, `"state":"PENDING"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	wantFrom := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	wantTo := time.Date(2026, 7, 31, 23, 59, 59, 0, time.UTC)
	if !ev.request.RangeFrom.Equal(wantFrom) || !ev.request.RangeTo.Equal(wantTo) || ev.request.RepositoryID != "repo-a" {
		t.Fatalf("request = %+v", ev.request)
	}
	// Identity came from the session, never from the body.
	if ev.read.TenantID != "tenant-a" || ev.read.ActorID != "actor-a" || ev.read.RequestID == "" {
		t.Fatalf("context = %+v", ev.read)
	}
}

// A request without a session, a malformed body, or a range that is not
// closed is the same coarse refusal as everything else, and none of them
// reaches the backend (SPEC-0031 AC1, SPEC-0001).
func TestRequestPackMalformedInputIsCoarse(t *testing.T) {
	for _, body := range []string{
		`{not json`,
		`{}`,
		`{"range_from":"2026-07-01T00:00:00Z"}`,
		`{"range_from":"not-a-date","range_to":"2026-07-31T23:59:59Z"}`,
		`{"range_from":"2026-07-31T23:59:59Z","range_to":"2026-07-01T00:00:00Z"}`,
	} {
		ev := &stubEvidence{}
		response := serveEvidence(t, NewEvidence(ev, session()), http.MethodPost, "/api/v1/audit/evidence-packs", body)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", body, response.Code)
		}
		if ev.calls != 0 {
			t.Fatalf("%s: backend was called for a malformed request", body)
		}
	}
	ev := &stubEvidence{}
	response := serveEvidence(t, NewEvidence(ev, stubSession{}), http.MethodPost, "/api/v1/audit/evidence-packs", packBody)
	if response.Code != http.StatusNotFound || ev.calls != 0 {
		t.Fatalf("no-session: status = %d, calls = %d", response.Code, ev.calls)
	}
}

// The assembly status is shaped field for field: per-section counts and a
// declared SOURCE_UNAVAILABLE gap travel exactly as the backend reported
// them — a degraded section is never rendered complete here (SPEC-0032 AC8).
func TestPackStatusForwardsDegradedSections(t *testing.T) {
	from := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	ev := &stubEvidence{status: audit.PackStatus{
		State: audit.PackReady,
		Sections: []audit.SectionStatus{
			{Type: audit.SectionApprovals, RecordCount: 3},
			{Type: audit.SectionAccessChanges, RecordCount: 0, Gaps: []audit.SectionGap{{
				From: from.AddDate(0, 0, 9), To: from.AddDate(0, 0, 11), Reason: audit.GapSourceUnavailable,
			}}},
		},
		AppendixRecordCount: 2, RangeFrom: from, RangeTo: to, RepositoryID: "repo-a",
	}}
	response := serveEvidence(t, NewEvidence(ev, session()), http.MethodGet, "/api/v1/audit/evidence-packs/pack-1/status", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if ev.packID != "pack-1" {
		t.Fatalf("pack id = %q", ev.packID)
	}
	body := response.Body.String()
	for _, want := range []string{
		`"state":"READY"`, `"type":"ACCESS_CHANGES"`, `"reason":"SOURCE_UNAVAILABLE"`,
		`"appendix_record_count":2`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %s: %s", want, body)
		}
	}
	// The gap renders with its bounds, and the degraded section says so.
	var view PackStatusView
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(view.Sections) != 2 || len(view.Sections[1].Gaps) != 1 ||
		view.Sections[1].Gaps[0].Reason != "SOURCE_UNAVAILABLE" {
		t.Fatalf("view = %+v", view)
	}
}

// A backend refusal on status or retrieval is one coarse 404 that
// distinguishes nothing (SPEC-0001).
func TestPackReadsAreCoarseOnRefusal(t *testing.T) {
	refusal := errors.New("audit: evidence pack unavailable")
	for _, target := range []string{
		"/api/v1/audit/evidence-packs/pack-1/status",
		"/api/v1/audit/evidence-packs/pack-1",
	} {
		ev := &stubEvidence{err: refusal}
		response := serveEvidence(t, NewEvidence(ev, session()), http.MethodGet, target, "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", target, response.Code)
		}
	}
	// No session is the same refusal and never reaches the backend.
	ev := &stubEvidence{}
	response := serveEvidence(t, NewEvidence(ev, stubSession{}), http.MethodGet, "/api/v1/audit/evidence-packs/pack-1/status", "")
	if response.Code != http.StatusNotFound || ev.calls != 0 {
		t.Fatalf("no-session: status = %d, calls = %d", response.Code, ev.calls)
	}
}

// A READY pack streams as newline-delimited JSON chunks in wire order —
// header, control sections, appendix, closing chunk — each shaped field for
// field, the attested appendix's label and provenance block included
// (SPEC-0032 non-functional, AC7).
func TestGetPackStreamsNDJSONChunks(t *testing.T) {
	when := time.Date(2026, 7, 2, 9, 30, 0, 0, time.UTC)
	ev := &stubEvidence{chunks: []audit.Chunk{
		{ChunkIndex: 0, Header: &audit.PackHeader{
			PackID: "pack-1", TenantID: "tenant-a", RangeFrom: when, RangeTo: when.Add(24 * time.Hour),
			RequestedBy: "actor-a", DecisionID: "decision-1", GeneratedAt: when,
		}},
		{ChunkIndex: 1, Section: &audit.ControlSection{
			Type: audit.SectionApprovals, Complete: true,
			Anchors:       &audit.ChainAnchor{FirstSeq: 1, LastSeq: 2, FirstRecordHash: "h1", LastRecordHash: "h2", PrevRecordHash: "h0"},
			Records:       []audit.ControlRecord{{ChainSeq: 1, RecordHash: "rec", ActorID: "actor-a", Resource: "mr-1", Action: "merge_request.merge", Allowed: true, OccurredAt: when, Approval: &audit.ApprovalDetail{MergeRequestID: "mr-1"}}},
			RecordsDigest: "sha256:section",
		}},
		{ChunkIndex: 2, Appendix: &audit.Appendix{
			Label: "attested imported history — display-only",
			Groups: []audit.ImportGroup{{Records: []audit.AppendixRecord{{
				RecordKind: "merge_request", SourceRef: "foreign-1", Payload: []byte(`{}`),
				PayloadMediaType: "application/json",
				Provenance:       &audit.Provenance{Class: "ATTESTED_IMPORT", ImportID: "import-1", DeclaredActor: "someone@example.com"},
			}}}},
		}},
		{ChunkIndex: 3, Final: true},
	}}
	response := serveEvidence(t, NewEvidence(ev, session()), http.MethodGet, "/api/v1/audit/evidence-packs/pack-1", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/x-ndjson" {
		t.Fatalf("content type = %q", contentType)
	}
	lines := strings.Split(strings.TrimSpace(response.Body.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines = %d", len(lines))
	}
	var header PackChunkView
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatalf("header line: %v", err)
	}
	if header.Header == nil || header.Header.PackID != "pack-1" || header.Header.DecisionID != "decision-1" {
		t.Fatalf("header = %+v", header)
	}
	var section PackChunkView
	if err := json.Unmarshal([]byte(lines[1]), &section); err != nil {
		t.Fatalf("section line: %v", err)
	}
	if section.Section == nil || section.Section.Type != "APPROVALS" || !section.Section.Complete ||
		section.Section.Anchors == nil || section.Section.Anchors.PrevRecordHash != "h0" ||
		len(section.Section.Records) != 1 || section.Section.Records[0].Approval == nil {
		t.Fatalf("section = %+v", section)
	}
	var appendix PackChunkView
	if err := json.Unmarshal([]byte(lines[2]), &appendix); err != nil {
		t.Fatalf("appendix line: %v", err)
	}
	if appendix.Appendix == nil || appendix.Appendix.Label != "attested imported history — display-only" ||
		len(appendix.Appendix.Groups) != 1 ||
		appendix.Appendix.Groups[0].Records[0].Provenance.Class != "ATTESTED_IMPORT" {
		t.Fatalf("appendix = %+v", appendix)
	}
	var final PackChunkView
	if err := json.Unmarshal([]byte(lines[3]), &final); err != nil {
		t.Fatalf("final line: %v", err)
	}
	if !final.FinalChunk || final.ChunkIndex != 3 {
		t.Fatalf("final = %+v", final)
	}
}
