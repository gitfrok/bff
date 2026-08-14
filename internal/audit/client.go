// Package audit adapts the generated EvidenceService gRPC client onto
// BFF-shaped request/response types. It carries verified identity and shapes
// only (SPEC-0031, SPEC-0032, T-0026): the backend is the PDP for
// evidence.pack.generate and evidence.pack.read, assembly is entirely
// server-determined, and nothing here filters, assembles, or authorizes
// (invariant 18). A section the backend reports degraded — gaps, counts and
// reasons included — is forwarded exactly as reported; a partial section is
// never rendered complete here.
package audit

import (
	"context"
	"errors"
	"io"
	"time"

	auditv1 "github.com/gitfrok/bff/gen/proto/audit/v1"
	contractsv1 "github.com/gitfrok/bff/gen/proto/contracts/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ErrMalformed refuses a request whose shape the contract does not name. It
// is coarse: the caller learns nothing about what exists or what is allowed.
var ErrMalformed = errors.New("audit: malformed request")

// PackState names the lifecycle of an asynchronous assembly (SPEC-0031).
type PackState string

const (
	PackPending    PackState = "PENDING"
	PackAssembling PackState = "ASSEMBLING"
	PackReady      PackState = "READY"
	PackFailed     PackState = "FAILED"
)

func packStateOf(wire auditv1.PackState) PackState {
	switch wire {
	case auditv1.PackState_PACK_STATE_PENDING:
		return PackPending
	case auditv1.PackState_PACK_STATE_ASSEMBLING:
		return PackAssembling
	case auditv1.PackState_PACK_STATE_READY:
		return PackReady
	case auditv1.PackState_PACK_STATE_FAILED:
		return PackFailed
	default:
		return ""
	}
}

// SectionType names the four control sections a pack always carries
// (SPEC-0031 AC1). The labelled appendix is deliberately not one.
type SectionType string

const (
	SectionApprovals       SectionType = "APPROVALS"
	SectionPolicyDecisions SectionType = "POLICY_DECISIONS"
	SectionScanGates       SectionType = "SCAN_GATES"
	SectionAccessChanges   SectionType = "ACCESS_CHANGES"
)

func sectionTypeOf(wire auditv1.SectionType) SectionType {
	switch wire {
	case auditv1.SectionType_SECTION_TYPE_APPROVALS:
		return SectionApprovals
	case auditv1.SectionType_SECTION_TYPE_POLICY_DECISIONS:
		return SectionPolicyDecisions
	case auditv1.SectionType_SECTION_TYPE_SCAN_GATES:
		return SectionScanGates
	case auditv1.SectionType_SECTION_TYPE_ACCESS_CHANGES:
		return SectionAccessChanges
	default:
		return ""
	}
}

// GapReason names why a section could not be fully assembled for part of the
// range (SPEC-0032 AC8). The reason is forwarded as reported, never
// substituted.
type GapReason string

const (
	GapSourceUnavailable GapReason = "SOURCE_UNAVAILABLE"
	GapProjectionLagged  GapReason = "PROJECTION_LAGGED"
	GapAssemblyFailed    GapReason = "ASSEMBLY_FAILED"
)

func gapReasonOf(wire auditv1.GapReason) GapReason {
	switch wire {
	case auditv1.GapReason_GAP_REASON_SOURCE_UNAVAILABLE:
		return GapSourceUnavailable
	case auditv1.GapReason_GAP_REASON_PROJECTION_LAGGED:
		return GapProjectionLagged
	case auditv1.GapReason_GAP_REASON_ASSEMBLY_FAILED:
		return GapAssemblyFailed
	default:
		return ""
	}
}

// PackRequest asks for a pack over one closed date range and an optional
// repository scope — the only two things the contract lets a caller name
// (SPEC-0032 AC4). No record list, section filter, or retention override has
// a field to travel in.
type PackRequest struct {
	RangeFrom    time.Time
	RangeTo      time.Time
	RepositoryID string
}

// PackReference is the pack identity the request produced, with the state
// the assembly is in.
type PackReference struct {
	PackID string
	State  PackState
}

// SectionGap is one explicit marker that part of a section's range could not
// be assembled, with its inclusive bounds.
type SectionGap struct {
	From   time.Time
	To     time.Time
	Reason GapReason
}

// SectionStatus is one section's live assembly view: its record count so far
// and the gaps declared for it.
type SectionStatus struct {
	Type        SectionType
	RecordCount int64
	Gaps        []SectionGap
}

// PackStatus is the observable assembly state of one pack (SPEC-0031
// non-functional). Counts are statistics, never record content.
type PackStatus struct {
	State               PackState
	FailureReason       string
	Sections            []SectionStatus
	AppendixRecordCount int64
	RangeFrom           time.Time
	RangeTo             time.Time
	RepositoryID        string
}

// ChainAnchor bounds a section's cited slice of the append-only chain
// (ADR-0007): the verification data a consumer re-derives the pack against.
type ChainAnchor struct {
	FirstSeq        int64
	LastSeq         int64
	FirstRecordHash string
	LastRecordHash  string
	PrevRecordHash  string
}

// ApprovalDetail is the approval-specific detail of a control record.
type ApprovalDetail struct {
	MergeRequestID   string
	ProtectionRuleID string
}

// PolicyDecisionDetail is the policy-decision-specific detail of a control
// record: the deciding policy version and the input digest. Mode is always
// ENFORCED in a control section — a dry-run decision is not representable
// there (SPEC-0032 AC3).
type PolicyDecisionDetail struct {
	DecisionID     string
	BundleRevision string
	InputDigest    string
	Mode           string
}

// ScanGateDetail is the scan-gate-specific detail of a control record.
type ScanGateDetail struct {
	MergeRequestID      string
	ScanID              string
	ReliedUponTriageIDs []string
}

// AccessChangeDetail is the access-change-specific detail of a control
// record.
type AccessChangeDetail struct {
	AccessKind        string
	TargetPrincipalID string
	GrantID           string
}

// ControlRecord is one cited record of a control section. Exactly one of the
// detail pointers is set; which one is determined by the section's type.
type ControlRecord struct {
	ChainSeq       int64
	RecordHash     string
	ActorID        string
	Resource       string
	Action         string
	Allowed        bool
	OccurredAt     time.Time
	Approval       *ApprovalDetail
	PolicyDecision *PolicyDecisionDetail
	ScanGate       *ScanGateDetail
	AccessChange   *AccessChangeDetail
}

// ControlSection is one of the four sections a pack carries: its embedded
// records, its chain anchors, and its explicit gaps. A section reported
// incomplete travels incomplete — Complete false with its gaps (SPEC-0032
// AC8).
type ControlSection struct {
	Type          SectionType
	Anchors       *ChainAnchor
	Complete      bool
	Gaps          []SectionGap
	Records       []ControlRecord
	RecordsDigest string
}

// Provenance is an attested record's provenance block (ADR-0029 §2). It
// exists only in appendix shapes: nothing in a control section can carry it.
type Provenance struct {
	Class          string
	ImportID       string
	SourceSystem   string
	SourceInstance string
	SourceRef      string
	DeclaredActor  string
	DeclaredAt     time.Time
	PayloadDigest  string
}

// HistoryImported is the admitting HistoryImported event embedded in the
// appendix (events/audit/v1.HistoryImported).
type HistoryImported struct {
	EventID        string
	ActorID        string
	RepositoryID   string
	ImportID       string
	SourceSystem   string
	SourceInstance string
	RecordCounts   map[string]int64
	ManifestDigest string
	OccurredAt     time.Time
}

// AppendixRecord is one attested imported record, labelled as foreign
// history and carrying its payload and provenance block.
type AppendixRecord struct {
	RecordKind       string
	SourceRef        string
	Payload          []byte
	PayloadMediaType string
	Provenance       *Provenance
}

// ImportGroup is one import's contribution to the appendix: the admitting
// event and the records it admitted.
type ImportGroup struct {
	HistoryImported *HistoryImported
	Records         []AppendixRecord
}

// Appendix is the labelled appendix carrying attested imported history
// (SPEC-0031 AC2). The label is server-set and travels with the records.
type Appendix struct {
	Label  string
	Groups []ImportGroup
}

// PackHeader is the pack's identity, range, scope and generation provenance
// — the first chunk of every retrieval.
type PackHeader struct {
	PackID       string
	TenantID     string
	RangeFrom    time.Time
	RangeTo      time.Time
	RepositoryID string
	RequestedBy  string
	DecisionID   string
	GeneratedAt  time.Time
}

// Chunk is one bounded chunk of a READY pack, in stream order: the header
// first, then one control section per chunk in SectionType order, then the
// appendix chunks. Exactly one of Header, Section and Appendix is set.
type Chunk struct {
	ChunkIndex int64
	Final      bool
	Header     *PackHeader
	Section    *ControlSection
	Appendix   *Appendix
}

// Client talks to the backend's EvidenceService.
type Client struct {
	service auditv1.EvidenceServiceClient
}

// New wires the adapter onto the generated client.
func New(service auditv1.EvidenceServiceClient) *Client {
	return &Client{service: service}
}

// contextOf maps the verified session identity onto the wire context. The
// actor ID and roles are verified server-side; a caller cannot assert them
// (SPEC-0032).
func contextOf(read aggregate.ReadContext) *auditv1.EvidenceContext {
	return &auditv1.EvidenceContext{
		TenantId:   read.TenantID,
		ActorId:    read.ActorID,
		ActorRoles: append([]string(nil), read.ActorRoles...),
		RequestId:  read.RequestID,
	}
}

// ValidatePackRequest reports whether the request is one the contract names:
// a closed range — both bounds present and from not after to (SPEC-0031
// AC1). The HTTP surface uses it to refuse an open range before anything
// reaches the backend; RequestPack enforces the same rule.
func ValidatePackRequest(in PackRequest) bool {
	return !in.RangeFrom.IsZero() && !in.RangeTo.IsZero() && !in.RangeFrom.After(in.RangeTo)
}

// RequestPack starts the asynchronous assembly of a pack over one closed
// date range. The range must be closed: both bounds present and from not
// after to — anything else is a shape the contract does not name and is
// refused before anything reaches the backend (SPEC-0031 AC1).
func (c *Client) RequestPack(ctx context.Context, read aggregate.ReadContext, in PackRequest) (PackReference, error) {
	if !ValidatePackRequest(in) {
		return PackReference{}, ErrMalformed
	}
	response, err := c.service.RequestEvidencePack(ctx, &auditv1.RequestEvidencePackRequest{
		Context:      contextOf(read),
		RangeFrom:    timestamppb.New(in.RangeFrom),
		RangeTo:      timestamppb.New(in.RangeTo),
		RepositoryId: in.RepositoryID,
	})
	if err != nil {
		return PackReference{}, err
	}
	return PackReference{PackID: response.GetPackId(), State: packStateOf(response.GetState())}, nil
}

// PackStatus reads the assembly state of one pack. Not-found, cross-tenant
// and unauthorized are the same backend refusal and pass through untouched
// (SPEC-0001).
func (c *Client) PackStatus(ctx context.Context, read aggregate.ReadContext, packID string) (PackStatus, error) {
	if packID == "" {
		return PackStatus{}, ErrMalformed
	}
	response, err := c.service.GetEvidencePackStatus(ctx, &auditv1.GetEvidencePackStatusRequest{
		Context: contextOf(read),
		PackId:  packID,
	})
	if err != nil {
		return PackStatus{}, err
	}
	status := PackStatus{
		State:               packStateOf(response.GetState()),
		FailureReason:       response.GetFailureReason(),
		Sections:            make([]SectionStatus, 0, len(response.GetSections())),
		AppendixRecordCount: response.GetAppendixRecordCount(),
		RepositoryID:        response.GetRepositoryId(),
	}
	if t := response.GetRangeFrom(); t != nil {
		status.RangeFrom = t.AsTime()
	}
	if t := response.GetRangeTo(); t != nil {
		status.RangeTo = t.AsTime()
	}
	for _, section := range response.GetSections() {
		shaped := SectionStatus{Type: sectionTypeOf(section.GetType()), RecordCount: section.GetRecordCount()}
		for _, gap := range section.GetGaps() {
			shaped.Gaps = append(shaped.Gaps, shapeGap(gap))
		}
		status.Sections = append(status.Sections, shaped)
	}
	return status, nil
}

// GetPack retrieves a READY pack as an ordered stream of bounded chunks,
// handing each shaped chunk to send as it arrives (SPEC-0032 non-functional).
// No chunk is buffered ahead of its consumer and the adapter holds no full
// pack in memory.
func (c *Client) GetPack(ctx context.Context, read aggregate.ReadContext, packID string, send func(Chunk) error) error {
	if packID == "" {
		return ErrMalformed
	}
	stream, err := c.service.GetEvidencePack(ctx, &auditv1.GetEvidencePackRequest{
		Context: contextOf(read),
		PackId:  packID,
	})
	if err != nil {
		return err
	}
	for {
		response, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := send(shapeChunk(response)); err != nil {
			return err
		}
	}
}

func shapeGap(gap *auditv1.SectionGap) SectionGap {
	shaped := SectionGap{Reason: gapReasonOf(gap.GetReason())}
	if t := gap.GetFrom(); t != nil {
		shaped.From = t.AsTime()
	}
	if t := gap.GetTo(); t != nil {
		shaped.To = t.AsTime()
	}
	return shaped
}

func shapeChunk(response *auditv1.GetEvidencePackResponse) Chunk {
	chunk := Chunk{ChunkIndex: response.GetChunkIndex(), Final: response.GetFinalChunk()}
	switch content := response.GetContent().(type) {
	case *auditv1.GetEvidencePackResponse_Header:
		chunk.Header = shapeHeader(content.Header)
	case *auditv1.GetEvidencePackResponse_Section:
		chunk.Section = shapeSection(content.Section)
	case *auditv1.GetEvidencePackResponse_Appendix:
		chunk.Appendix = shapeAppendix(content.Appendix)
	}
	return chunk
}

func shapeHeader(pack *auditv1.EvidencePack) *PackHeader {
	header := PackHeader{
		PackID:       pack.GetPackId(),
		TenantID:     pack.GetTenantId(),
		RepositoryID: pack.GetRepositoryId(),
		RequestedBy:  pack.GetRequestedBy(),
		DecisionID:   pack.GetDecisionId(),
	}
	if t := pack.GetRangeFrom(); t != nil {
		header.RangeFrom = t.AsTime()
	}
	if t := pack.GetRangeTo(); t != nil {
		header.RangeTo = t.AsTime()
	}
	if t := pack.GetGeneratedAt(); t != nil {
		header.GeneratedAt = t.AsTime()
	}
	return &header
}

func shapeSection(section *auditv1.ControlSection) *ControlSection {
	shaped := ControlSection{
		Type:          sectionTypeOf(section.GetType()),
		Complete:      section.GetComplete(),
		Gaps:          make([]SectionGap, 0, len(section.GetGaps())),
		Records:       make([]ControlRecord, 0, len(section.GetRecords())),
		RecordsDigest: section.GetRecordsDigest(),
	}
	if anchors := section.GetAnchors(); anchors != nil {
		shaped.Anchors = &ChainAnchor{
			FirstSeq:        anchors.GetFirstSeq(),
			LastSeq:         anchors.GetLastSeq(),
			FirstRecordHash: anchors.GetFirstRecordHash(),
			LastRecordHash:  anchors.GetLastRecordHash(),
			PrevRecordHash:  anchors.GetPrevRecordHash(),
		}
	}
	for _, gap := range section.GetGaps() {
		shaped.Gaps = append(shaped.Gaps, shapeGap(gap))
	}
	for _, record := range section.GetRecords() {
		shaped.Records = append(shaped.Records, shapeRecord(record))
	}
	return &shaped
}

func shapeRecord(record *auditv1.ControlSectionRecord) ControlRecord {
	shaped := ControlRecord{
		ChainSeq:   record.GetChainSeq(),
		RecordHash: record.GetRecordHash(),
		ActorID:    record.GetActorId(),
		Resource:   record.GetResource(),
		Action:     record.GetAction(),
		Allowed:    record.GetAllowed(),
	}
	if t := record.GetOccurredAt(); t != nil {
		shaped.OccurredAt = t.AsTime()
	}
	switch detail := record.GetDetail().(type) {
	case *auditv1.ControlSectionRecord_Approval:
		shaped.Approval = &ApprovalDetail{
			MergeRequestID:   detail.Approval.GetMergeRequestId(),
			ProtectionRuleID: detail.Approval.GetProtectionRuleId(),
		}
	case *auditv1.ControlSectionRecord_PolicyDecision:
		shaped.PolicyDecision = &PolicyDecisionDetail{
			DecisionID:     detail.PolicyDecision.GetDecisionId(),
			BundleRevision: detail.PolicyDecision.GetBundleRevision(),
			InputDigest:    detail.PolicyDecision.GetInputDigest(),
			Mode:           controlModeName(detail.PolicyDecision.GetMode()),
		}
	case *auditv1.ControlSectionRecord_ScanGate:
		shaped.ScanGate = &ScanGateDetail{
			MergeRequestID:      detail.ScanGate.GetMergeRequestId(),
			ScanID:              detail.ScanGate.GetScanId(),
			ReliedUponTriageIDs: append([]string(nil), detail.ScanGate.GetReliedUponTriageIds()...),
		}
	case *auditv1.ControlSectionRecord_AccessChange:
		shaped.AccessChange = &AccessChangeDetail{
			AccessKind:        detail.AccessChange.GetAccessKind(),
			TargetPrincipalID: detail.AccessChange.GetTargetPrincipalId(),
			GrantID:           detail.AccessChange.GetGrantId(),
		}
	}
	return shaped
}

// controlModeName renders the closed control-decision mode enum. ENFORCED is
// the only value a control section admits; anything else renders empty
// rather than inventing a name (SPEC-0032 AC3).
func controlModeName(mode auditv1.ControlDecisionMode) string {
	if mode == auditv1.ControlDecisionMode_CONTROL_DECISION_MODE_ENFORCED {
		return "ENFORCED"
	}
	return ""
}

func shapeAppendix(appendix *auditv1.AttestedAppendix) *Appendix {
	shaped := Appendix{Label: appendix.GetLabel(), Groups: make([]ImportGroup, 0, len(appendix.GetGroups()))}
	for _, group := range appendix.GetGroups() {
		shapedGroup := ImportGroup{Records: make([]AppendixRecord, 0, len(group.GetRecords()))}
		if event := group.GetHistoryImported(); event != nil {
			imported := &HistoryImported{
				EventID:        event.GetEventId(),
				ActorID:        event.GetActorId(),
				RepositoryID:   event.GetRepositoryId(),
				ImportID:       event.GetImportId(),
				SourceSystem:   event.GetSourceSystem(),
				SourceInstance: event.GetSourceInstance(),
				ManifestDigest: event.GetManifestDigest(),
			}
			if len(event.GetRecordCounts()) > 0 {
				imported.RecordCounts = make(map[string]int64, len(event.GetRecordCounts()))
				for kind, count := range event.GetRecordCounts() {
					imported.RecordCounts[kind] = count
				}
			}
			if t := event.GetOccurredAt(); t != nil {
				imported.OccurredAt = t.AsTime()
			}
			shapedGroup.HistoryImported = imported
		}
		for _, record := range group.GetRecords() {
			shapedRecord := AppendixRecord{
				RecordKind:       record.GetRecordKind(),
				SourceRef:        record.GetSourceRef(),
				Payload:          record.GetPayload(),
				PayloadMediaType: record.GetPayloadMediaType(),
			}
			if provenance := record.GetProvenance(); provenance != nil {
				shaped := &Provenance{
					Class:          provenanceClassName(provenance.GetClass()),
					ImportID:       provenance.GetImportId(),
					SourceSystem:   provenance.GetSourceSystem(),
					SourceInstance: provenance.GetSourceInstance(),
					SourceRef:      provenance.GetSourceRef(),
					DeclaredActor:  provenance.GetDeclaredActor(),
					PayloadDigest:  provenance.GetPayloadDigest(),
				}
				if t := provenance.GetDeclaredAt(); t != nil {
					shaped.DeclaredAt = t.AsTime()
				}
				shapedRecord.Provenance = shaped
			}
			shapedGroup.Records = append(shapedGroup.Records, shapedRecord)
		}
		shaped.Groups = append(shaped.Groups, shapedGroup)
	}
	return &shaped
}

func provenanceClassName(class contractsv1.Provenance_Class) string {
	switch class {
	case contractsv1.Provenance_CLASS_FIRST_PARTY:
		return "FIRST_PARTY"
	case contractsv1.Provenance_CLASS_ATTESTED_IMPORT:
		return "ATTESTED_IMPORT"
	default:
		return ""
	}
}
