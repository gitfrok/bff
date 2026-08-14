package audit

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	auditv1 "github.com/gitfrok/bff/gen/proto/audit/v1"
	contractsv1 "github.com/gitfrok/bff/gen/proto/contracts/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeStream is a canned pack chunk stream.
type fakeStream struct {
	chunks []*auditv1.GetEvidencePackResponse
	index  int
	err    error
}

func (f *fakeStream) Recv() (*auditv1.GetEvidencePackResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.index >= len(f.chunks) {
		return nil, io.EOF
	}
	chunk := f.chunks[f.index]
	f.index++
	return chunk, nil
}

func (f *fakeStream) Header() (metadata.MD, error) { return nil, nil }
func (f *fakeStream) Trailer() metadata.MD         { return nil }
func (f *fakeStream) CloseSend() error             { return nil }
func (f *fakeStream) Context() context.Context     { return context.Background() }
func (f *fakeStream) SendMsg(any) error            { return nil }
func (f *fakeStream) RecvMsg(any) error            { return nil }

// fakeService records what crossed the wire and answers with canned
// responses.
type fakeService struct {
	requestReq *auditv1.RequestEvidencePackRequest
	statusReq  *auditv1.GetEvidencePackStatusRequest
	getReq     *auditv1.GetEvidencePackRequest
	requestRes *auditv1.RequestEvidencePackResponse
	statusRes  *auditv1.GetEvidencePackStatusResponse
	stream     *fakeStream
	err        error
}

func (f *fakeService) RequestEvidencePack(_ context.Context, req *auditv1.RequestEvidencePackRequest, _ ...grpc.CallOption) (*auditv1.RequestEvidencePackResponse, error) {
	f.requestReq = req
	return f.requestRes, f.err
}

func (f *fakeService) GetEvidencePackStatus(_ context.Context, req *auditv1.GetEvidencePackStatusRequest, _ ...grpc.CallOption) (*auditv1.GetEvidencePackStatusResponse, error) {
	f.statusReq = req
	return f.statusRes, f.err
}

func (f *fakeService) GetEvidencePack(_ context.Context, req *auditv1.GetEvidencePackRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[auditv1.GetEvidencePackResponse], error) {
	f.getReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.stream, nil
}

func read() aggregate.ReadContext {
	return aggregate.ReadContext{
		TenantID: "tenant-a", ActorID: "actor-a", RequestID: "request-a",
		ActorRoles: []string{"compliance_owner"},
	}
}

// The wire context carries exactly the session's verified identity — tenant,
// actor, roles, request ID — and the contract gives a pack request no field
// to assert anything else: only the closed range and an optional repository
// scope cross the wire (SPEC-0032 AC4).
func TestRequestPackForwardsIdentityOnly(t *testing.T) {
	from := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 31, 23, 59, 59, 0, time.UTC)
	f := &fakeService{requestRes: &auditv1.RequestEvidencePackResponse{PackId: "pack-1", State: auditv1.PackState_PACK_STATE_PENDING}}
	pack, err := New(f).RequestPack(context.Background(), read(), PackRequest{RangeFrom: from, RangeTo: to, RepositoryID: "repo-a"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if pack.PackID != "pack-1" || pack.State != PackPending {
		t.Fatalf("pack = %+v", pack)
	}
	ctx := f.requestReq.GetContext()
	if ctx.GetTenantId() != "tenant-a" || ctx.GetActorId() != "actor-a" || ctx.GetRequestId() != "request-a" {
		t.Fatalf("context = %v", ctx)
	}
	//arch:allow-inline-authz this compares a forwarded role string for equality in a test; it grants nothing
	if len(ctx.GetActorRoles()) != 1 || ctx.GetActorRoles()[0] != "compliance_owner" {
		t.Fatalf("roles = %v", ctx.GetActorRoles())
	}
	if !f.requestReq.GetRangeFrom().AsTime().Equal(from) || !f.requestReq.GetRangeTo().AsTime().Equal(to) {
		t.Fatalf("range = %v", f.requestReq)
	}
	if f.requestReq.GetRepositoryId() != "repo-a" {
		t.Fatalf("repository = %v", f.requestReq)
	}
}

// The range is closed or the request is refused before anything reaches the
// backend: a missing bound or from after to is a shape the contract does not
// name (SPEC-0031 AC1).
func TestRequestPackRejectsOpenRange(t *testing.T) {
	when := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	later := when.Add(24 * time.Hour)
	for _, request := range []PackRequest{
		{},
		{RangeFrom: when},
		{RangeTo: when},
		{RangeFrom: later, RangeTo: when},
	} {
		f := &fakeService{}
		_, err := New(f).RequestPack(context.Background(), read(), request)
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("%+v: err = %v, want ErrMalformed", request, err)
		}
		if f.requestReq != nil {
			t.Fatalf("%+v: backend was called for an open range", request)
		}
	}
}

// The assembly state is shaped field for field: per-section counts and the
// gaps the backend declared — a degraded section travels degraded, exactly
// as reported (SPEC-0032 AC8).
func TestPackStatusShapesSectionsAndGaps(t *testing.T) {
	from := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	gapFrom := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	gapTo := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	f := &fakeService{statusRes: &auditv1.GetEvidencePackStatusResponse{
		State: auditv1.PackState_PACK_STATE_READY,
		Sections: []*auditv1.SectionStatus{
			{Type: auditv1.SectionType_SECTION_TYPE_APPROVALS, RecordCount: 3},
			{Type: auditv1.SectionType_SECTION_TYPE_ACCESS_CHANGES, RecordCount: 0, Gaps: []*auditv1.SectionGap{{
				From: timestamppb.New(gapFrom), To: timestamppb.New(gapTo),
				Reason: auditv1.GapReason_GAP_REASON_SOURCE_UNAVAILABLE,
			}}},
		},
		AppendixRecordCount: 2,
		RangeFrom:           timestamppb.New(from),
		RangeTo:             timestamppb.New(to),
		RepositoryId:        "repo-a",
	}}
	status, err := New(f).PackStatus(context.Background(), read(), "pack-1")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if f.statusReq.GetPackId() != "pack-1" || f.statusReq.GetContext().GetTenantId() != "tenant-a" {
		t.Fatalf("request = %v", f.statusReq)
	}
	if status.State != PackReady || status.AppendixRecordCount != 2 || status.RepositoryID != "repo-a" ||
		!status.RangeFrom.Equal(from) || !status.RangeTo.Equal(to) {
		t.Fatalf("status = %+v", status)
	}
	if len(status.Sections) != 2 {
		t.Fatalf("sections = %+v", status.Sections)
	}
	gapped := status.Sections[1]
	if gapped.Type != SectionAccessChanges || gapped.RecordCount != 0 || len(gapped.Gaps) != 1 {
		t.Fatalf("access changes = %+v", gapped)
	}
	gap := gapped.Gaps[0]
	if gap.Reason != GapSourceUnavailable || !gap.From.Equal(gapFrom) || !gap.To.Equal(gapTo) {
		t.Fatalf("gap = %+v", gap)
	}
}

// An empty pack identity is refused before anything reaches the backend.
func TestPackSelectorsMustBeNamed(t *testing.T) {
	f := &fakeService{}
	if _, err := New(f).PackStatus(context.Background(), read(), ""); !errors.Is(err, ErrMalformed) {
		t.Fatalf("status err = %v, want ErrMalformed", err)
	}
	if err := New(f).GetPack(context.Background(), read(), "", func(Chunk) error { return nil }); !errors.Is(err, ErrMalformed) {
		t.Fatalf("get err = %v, want ErrMalformed", err)
	}
	if f.statusReq != nil || f.getReq != nil {
		t.Fatal("backend was called for an unnamed pack")
	}
}

// A READY pack arrives as an ordered sequence of bounded chunks — header,
// one control section, appendix — and every field is shaped untouched, the
// attested record's provenance block included (SPEC-0032 AC7).
func TestGetPackStreamsChunksInOrder(t *testing.T) {
	when := time.Date(2026, 7, 2, 9, 30, 0, 0, time.UTC)
	declared := time.Date(2024, 1, 5, 0, 0, 0, 0, time.UTC)
	f := &fakeService{stream: &fakeStream{chunks: []*auditv1.GetEvidencePackResponse{
		{ChunkIndex: 0, Content: &auditv1.GetEvidencePackResponse_Header{Header: &auditv1.EvidencePack{
			PackId: "pack-1", TenantId: "tenant-a",
			RangeFrom: timestamppb.New(when), RangeTo: timestamppb.New(when.Add(24 * time.Hour)),
			RequestedBy: "actor-a", DecisionId: "decision-1", GeneratedAt: timestamppb.New(when),
		}}},
		{ChunkIndex: 1, Content: &auditv1.GetEvidencePackResponse_Section{Section: &auditv1.ControlSection{
			Type: auditv1.SectionType_SECTION_TYPE_POLICY_DECISIONS, Complete: true,
			Anchors: &auditv1.ChainAnchor{FirstSeq: 10, LastSeq: 12, FirstRecordHash: "h1", LastRecordHash: "h2", PrevRecordHash: "h0"},
			Records: []*auditv1.ControlSectionRecord{{
				ChainSeq: 11, RecordHash: "rec-hash", ActorId: "actor-a", Resource: "repo-a",
				Action: "policy.decide", Allowed: true, OccurredAt: timestamppb.New(when),
				Detail: &auditv1.ControlSectionRecord_PolicyDecision{PolicyDecision: &auditv1.PolicyDecisionRecord{
					DecisionId: "decision-1", BundleRevision: "rev-7", InputDigest: "sha256:abc",
					Mode: auditv1.ControlDecisionMode_CONTROL_DECISION_MODE_ENFORCED,
				}},
			}},
			RecordsDigest: "sha256:section",
		}}},
		{ChunkIndex: 2, Content: &auditv1.GetEvidencePackResponse_Appendix{Appendix: &auditv1.AttestedAppendix{
			Label: "attested imported history — display-only",
			Groups: []*auditv1.AttestedImportGroup{{
				HistoryImported: &auditv1.HistoryImportedReference{
					EventId: "event-1", ActorId: "operator-a", ImportId: "import-1",
					SourceSystem: "github", RecordCounts: map[string]int64{"merge_request": 4},
					ManifestDigest: "sha256:manifest", OccurredAt: timestamppb.New(declared),
				},
				Records: []*auditv1.AttestedAppendixRecord{{
					RecordKind: "merge_request", SourceRef: "foreign-1",
					Payload: []byte(`{"title":"old"}`), PayloadMediaType: "application/json",
					Provenance: &contractsv1.Provenance{
						Class: contractsv1.Provenance_CLASS_ATTESTED_IMPORT, ImportId: "import-1",
						SourceSystem: "github", SourceRef: "foreign-1", DeclaredActor: "someone@example.com",
						DeclaredAt: timestamppb.New(declared), PayloadDigest: "sha256:payload",
					},
				}},
			}},
		}}},
		{ChunkIndex: 3, FinalChunk: true},
	}}}
	var chunks []Chunk
	err := New(f).GetPack(context.Background(), read(), "pack-1", func(chunk Chunk) error {
		chunks = append(chunks, chunk)
		return nil
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if f.getReq.GetPackId() != "pack-1" || f.getReq.GetContext().GetTenantId() != "tenant-a" {
		t.Fatalf("request = %v", f.getReq)
	}
	if len(chunks) != 4 {
		t.Fatalf("chunks = %d", len(chunks))
	}
	header := chunks[0].Header
	if header == nil || header.PackID != "pack-1" || header.RequestedBy != "actor-a" || header.DecisionID != "decision-1" ||
		!header.RangeFrom.Equal(when) {
		t.Fatalf("header = %+v", header)
	}
	section := chunks[1].Section
	if section == nil || section.Type != SectionPolicyDecisions || !section.Complete || section.RecordsDigest != "sha256:section" {
		t.Fatalf("section = %+v", section)
	}
	if section.Anchors == nil || section.Anchors.FirstSeq != 10 || section.Anchors.PrevRecordHash != "h0" {
		t.Fatalf("anchors = %+v", section.Anchors)
	}
	record := section.Records[0]
	if record.ChainSeq != 11 || record.Action != "policy.decide" || !record.Allowed || !record.OccurredAt.Equal(when) {
		t.Fatalf("record = %+v", record)
	}
	if record.PolicyDecision == nil || record.PolicyDecision.BundleRevision != "rev-7" || record.PolicyDecision.Mode != "ENFORCED" {
		t.Fatalf("policy decision = %+v", record.PolicyDecision)
	}
	appendix := chunks[2].Appendix
	if appendix == nil || appendix.Label != "attested imported history — display-only" || len(appendix.Groups) != 1 {
		t.Fatalf("appendix = %+v", appendix)
	}
	group := appendix.Groups[0]
	if group.HistoryImported == nil || group.HistoryImported.ImportID != "import-1" ||
		group.HistoryImported.RecordCounts["merge_request"] != 4 {
		t.Fatalf("history imported = %+v", group.HistoryImported)
	}
	attested := group.Records[0]
	if attested.RecordKind != "merge_request" || string(attested.Payload) != `{"title":"old"}` {
		t.Fatalf("attested = %+v", attested)
	}
	if attested.Provenance == nil || attested.Provenance.Class != "ATTESTED_IMPORT" ||
		attested.Provenance.DeclaredActor != "someone@example.com" || !attested.Provenance.DeclaredAt.Equal(declared) {
		t.Fatalf("provenance = %+v", attested.Provenance)
	}
	if !chunks[3].Final || chunks[3].ChunkIndex != 3 {
		t.Fatalf("final chunk = %+v", chunks[3])
	}
}

// A backend refusal passes through untouched; the coarse shape is applied by
// the HTTP surface, never by rewriting the reason here.
func TestBackendErrorPassesThrough(t *testing.T) {
	refusal := errors.New("audit: evidence pack unavailable")
	client := New(&fakeService{err: refusal})
	if _, err := client.RequestPack(context.Background(), read(), PackRequest{
		RangeFrom: time.Now(), RangeTo: time.Now().Add(time.Hour),
	}); !errors.Is(err, refusal) {
		t.Fatalf("request err = %v", err)
	}
	if _, err := client.PackStatus(context.Background(), read(), "pack-1"); !errors.Is(err, refusal) {
		t.Fatalf("status err = %v", err)
	}
	if err := client.GetPack(context.Background(), read(), "pack-1", func(Chunk) error { return nil }); !errors.Is(err, refusal) {
		t.Fatalf("get err = %v", err)
	}
}
