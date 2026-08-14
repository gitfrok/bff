// evidence.go is the date-ranged evidence pack surface (SPEC-0031, SPEC-0032,
// T-0026). The backend EvidenceService is the PDP for evidence.pack.generate
// and evidence.pack.read: assembly is entirely server-determined, generation
// and retrieval are authorized by the PDP with server-derived context and are
// themselves audited, and this surface forwards the session's verified
// identity and shapes only (SPEC-0032 AC10, invariant 18). A request accepts
// only a closed date range and an optional repository scope — no record
// list, section filter, or retention override has a field to travel in
// (SPEC-0032 AC4). A pack is retrieved as an ordered stream of bounded
// chunks, each shaped and written as it arrives (SPEC-0032 non-functional).
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/audit"
)

// Evidence is the evidence pack port this surface shapes. The backend owns
// every decision: authorization, assembly, section membership, gaps and
// verification data (SPEC-0031, SPEC-0032).
type Evidence interface {
	RequestPack(ctx context.Context, read aggregate.ReadContext, in audit.PackRequest) (audit.PackReference, error)
	PackStatus(ctx context.Context, read aggregate.ReadContext, packID string) (audit.PackStatus, error)
	GetPack(ctx context.Context, read aggregate.ReadContext, packID string, send func(audit.Chunk) error) error
}

// EvidenceHandler serves the evidence pack surface.
type EvidenceHandler struct {
	evidence Evidence
	session  Session
}

// NewEvidence wires the handler onto the evidence pack port.
func NewEvidence(evidence Evidence, session Session) *EvidenceHandler {
	return &EvidenceHandler{evidence: evidence, session: session}
}

// Routes returns the evidence pack surface. Identity never comes from these
// paths or parameters — only from the authenticated session.
func (h *EvidenceHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/audit/evidence-packs", h.requestPack)
	mux.HandleFunc("GET /api/v1/audit/evidence-packs/{pack_id}/status", h.packStatus)
	mux.HandleFunc("GET /api/v1/audit/evidence-packs/{pack_id}", h.getPack)
	return mux
}

// ServeHTTP lets the handler be registered directly on a parent mux, as the
// security handler does.
func (h *EvidenceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Routes().ServeHTTP(w, r)
}

// packRequestBody is the JSON shape the request posts. It mirrors the
// contract's RequestEvidencePackRequest minus everything the session
// supplies or the server computes: no tenant, actor, or role is
// caller-assertable, and the request names only the closed range and an
// optional repository scope (SPEC-0032 AC4).
type packRequestBody struct {
	RangeFrom    string `json:"range_from"`
	RangeTo      string `json:"range_to"`
	RepositoryID string `json:"repository_id"`
}

// maxPackRequestBodyBytes bounds the request body: a range and an optional
// repository ID is a handful of fields, and nothing legitimate approaches
// this.
const maxPackRequestBodyBytes = 16 << 10

// PackReferenceView is the pack identity now assembling, as the caller
// observes it.
type PackReferenceView struct {
	PackID string `json:"pack_id"`
	State  string `json:"state"`
}

// GapView is one explicit gap marker with its inclusive bounds.
type GapView struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Reason string    `json:"reason"`
}

// SectionStatusView is one section's live assembly view.
type SectionStatusView struct {
	Type        string    `json:"type"`
	RecordCount int64     `json:"record_count"`
	Gaps        []GapView `json:"gaps"`
}

// PackStatusView is the observable assembly state of one pack. Counts are
// statistics, never record content: the status surface carries no payload,
// source or provenance bytes (SPEC-0032 G9).
type PackStatusView struct {
	State               string              `json:"state"`
	FailureReason       string              `json:"failure_reason,omitempty"`
	Sections            []SectionStatusView `json:"sections"`
	AppendixRecordCount int64               `json:"appendix_record_count"`
	RangeFrom           time.Time           `json:"range_from"`
	RangeTo             time.Time           `json:"range_to"`
	RepositoryID        string              `json:"repository_id,omitempty"`
}

// AnchorView is one section's chain anchors: the verification data a
// consumer re-derives the pack against (SPEC-0032 AC7).
type AnchorView struct {
	FirstSeq        int64  `json:"first_seq"`
	LastSeq         int64  `json:"last_seq"`
	FirstRecordHash string `json:"first_record_hash"`
	LastRecordHash  string `json:"last_record_hash"`
	PrevRecordHash  string `json:"prev_record_hash"`
}

// ApprovalView is the approval detail of a control record.
type ApprovalView struct {
	MergeRequestID   string `json:"merge_request_id"`
	ProtectionRuleID string `json:"protection_rule_id"`
}

// PolicyDecisionView is the policy decision detail of a control record: the
// deciding policy version and the input digest (SPEC-0031 AC3).
type PolicyDecisionView struct {
	DecisionID     string `json:"decision_id"`
	BundleRevision string `json:"bundle_revision"`
	InputDigest    string `json:"input_digest"`
	Mode           string `json:"mode"`
}

// ScanGateView is the scan gate detail of a control record.
type ScanGateView struct {
	MergeRequestID      string   `json:"merge_request_id"`
	ScanID              string   `json:"scan_id"`
	ReliedUponTriageIDs []string `json:"relied_upon_triage_ids"`
}

// AccessChangeView is the access change detail of a control record.
type AccessChangeView struct {
	AccessKind        string `json:"access_kind"`
	TargetPrincipalID string `json:"target_principal_id"`
	GrantID           string `json:"grant_id"`
}

// ControlRecordView is one cited record of a control section. Exactly one of
// the detail fields is set, matching the section's type.
type ControlRecordView struct {
	ChainSeq       int64               `json:"chain_seq"`
	RecordHash     string              `json:"record_hash"`
	ActorID        string              `json:"actor_id"`
	Resource       string              `json:"resource"`
	Action         string              `json:"action"`
	Allowed        bool                `json:"allowed"`
	OccurredAt     time.Time           `json:"occurred_at"`
	Approval       *ApprovalView       `json:"approval,omitempty"`
	PolicyDecision *PolicyDecisionView `json:"policy_decision,omitempty"`
	ScanGate       *ScanGateView       `json:"scan_gate,omitempty"`
	AccessChange   *AccessChangeView   `json:"access_change,omitempty"`
}

// ControlSectionView is one of the four sections a pack carries, forwarded
// exactly as assembled: records, anchors, gaps and the completeness claim
// all come from the backend untouched — a degraded section is rendered
// degraded, never silently complete (SPEC-0032 AC8).
type ControlSectionView struct {
	Type          string              `json:"type"`
	Anchors       *AnchorView         `json:"anchors,omitempty"`
	Complete      bool                `json:"complete"`
	Gaps          []GapView           `json:"gaps"`
	Records       []ControlRecordView `json:"records"`
	RecordsDigest string              `json:"records_digest"`
}

// ProvenanceView is an attested record's provenance block (ADR-0029 §2). It
// appears only in appendix shapes.
type ProvenanceView struct {
	Class          string    `json:"class"`
	ImportID       string    `json:"import_id"`
	SourceSystem   string    `json:"source_system"`
	SourceInstance string    `json:"source_instance"`
	SourceRef      string    `json:"source_ref"`
	DeclaredActor  string    `json:"declared_actor"`
	DeclaredAt     time.Time `json:"declared_at"`
	PayloadDigest  string    `json:"payload_digest"`
}

// HistoryImportedView is the admitting HistoryImported event embedded in the
// appendix.
type HistoryImportedView struct {
	EventID        string           `json:"event_id"`
	ActorID        string           `json:"actor_id"`
	RepositoryID   string           `json:"repository_id"`
	ImportID       string           `json:"import_id"`
	SourceSystem   string           `json:"source_system"`
	SourceInstance string           `json:"source_instance"`
	RecordCounts   map[string]int64 `json:"record_counts,omitempty"`
	ManifestDigest string           `json:"manifest_digest"`
	OccurredAt     time.Time        `json:"occurred_at"`
}

// AppendixRecordView is one attested imported record, labelled as foreign
// history with its payload and provenance block.
type AppendixRecordView struct {
	RecordKind       string          `json:"record_kind"`
	SourceRef        string          `json:"source_ref"`
	Payload          []byte          `json:"payload"`
	PayloadMediaType string          `json:"payload_media_type"`
	Provenance       *ProvenanceView `json:"provenance,omitempty"`
}

// ImportGroupView is one import's contribution to the appendix.
type ImportGroupView struct {
	HistoryImported *HistoryImportedView `json:"history_imported,omitempty"`
	Records         []AppendixRecordView `json:"records"`
}

// AppendixView is the labelled appendix. The label is server-set and travels
// with the records so no renderer can drop it (ADR-0029 §6).
type AppendixView struct {
	Label  string            `json:"label"`
	Groups []ImportGroupView `json:"groups"`
}

// PackHeaderView is the pack's identity, range, scope and generation
// provenance.
type PackHeaderView struct {
	PackID       string    `json:"pack_id"`
	TenantID     string    `json:"tenant_id"`
	RangeFrom    time.Time `json:"range_from"`
	RangeTo      time.Time `json:"range_to"`
	RepositoryID string    `json:"repository_id,omitempty"`
	RequestedBy  string    `json:"requested_by"`
	DecisionID   string    `json:"decision_id"`
	GeneratedAt  time.Time `json:"generated_at"`
}

// PackChunkView is one bounded chunk of the pack stream, delivered as
// newline-delimited JSON in stream order. Exactly one of header, section and
// appendix is set per chunk, exactly as the backend sent it.
type PackChunkView struct {
	ChunkIndex int64               `json:"chunk_index"`
	FinalChunk bool                `json:"final_chunk"`
	Header     *PackHeaderView     `json:"header,omitempty"`
	Section    *ControlSectionView `json:"section,omitempty"`
	Appendix   *AppendixView       `json:"appendix,omitempty"`
}

// requestPack starts the asynchronous assembly of a pack over one closed
// date range. The range is closed or the request is refused: a missing bound
// or a range whose from is after its to is a shape the contract does not
// name, and it never reaches the backend (SPEC-0031 AC1).
func (h *EvidenceHandler) requestPack(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedEvidence(w)
		return
	}
	var in packRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPackRequestBodyBytes)).Decode(&in); err != nil {
		deniedEvidence(w)
		return
	}
	rangeFrom, err := time.Parse(time.RFC3339, in.RangeFrom)
	if err != nil {
		deniedEvidence(w)
		return
	}
	rangeTo, err := time.Parse(time.RFC3339, in.RangeTo)
	if err != nil {
		deniedEvidence(w)
		return
	}
	request := audit.PackRequest{
		RangeFrom:    rangeFrom,
		RangeTo:      rangeTo,
		RepositoryID: in.RepositoryID,
	}
	// A range that is not closed is refused here, before anything reaches
	// the backend — the same coarse shape as every other refusal.
	if !audit.ValidatePackRequest(request) {
		deniedEvidence(w)
		return
	}
	read.RequestID = newRequestID()
	pack, err := h.evidence.RequestPack(r.Context(), read, request)
	if err != nil {
		deniedEvidence(w)
		return
	}
	writeJSON(w, PackReferenceView{PackID: pack.PackID, State: string(pack.State)})
}

// packStatus observes assembly: the pack's state and per-section record
// counts, observable while a large range assembles (SPEC-0031
// non-functional).
func (h *EvidenceHandler) packStatus(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedEvidence(w)
		return
	}
	packID := r.PathValue("pack_id")
	if packID == "" {
		deniedEvidence(w)
		return
	}
	read.RequestID = newRequestID()
	status, err := h.evidence.PackStatus(r.Context(), read, packID)
	if err != nil {
		deniedEvidence(w)
		return
	}
	writeJSON(w, packStatusView(status))
}

// packStatusView shapes the assembly state field for field: gaps, counts and
// the failure reason come from the backend untouched.
func packStatusView(status audit.PackStatus) PackStatusView {
	view := PackStatusView{
		State:               string(status.State),
		FailureReason:       status.FailureReason,
		Sections:            make([]SectionStatusView, 0, len(status.Sections)),
		AppendixRecordCount: status.AppendixRecordCount,
		RangeFrom:           status.RangeFrom,
		RangeTo:             status.RangeTo,
		RepositoryID:        status.RepositoryID,
	}
	for _, section := range status.Sections {
		shaped := SectionStatusView{
			Type:        string(section.Type),
			RecordCount: section.RecordCount,
			Gaps:        make([]GapView, 0, len(section.Gaps)),
		}
		for _, gap := range section.Gaps {
			shaped.Gaps = append(shaped.Gaps, gapView(gap))
		}
		view.Sections = append(view.Sections, shaped)
	}
	return view
}

func gapView(gap audit.SectionGap) GapView {
	return GapView{From: gap.From, To: gap.To, Reason: string(gap.Reason)}
}

// getPack streams a READY pack to the caller as newline-delimited JSON
// chunks: each bounded chunk is shaped and written as it arrives, in stream
// order — header first, then the control sections in SectionType order, then
// the appendix (SPEC-0032 non-functional). Not-found, cross-tenant,
// unauthorized and not-yet-ready are the same coarse refusal (SPEC-0001), so
// the stream is only opened once the first chunk has been authorized and
// received.
func (h *EvidenceHandler) getPack(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedEvidence(w)
		return
	}
	packID := r.PathValue("pack_id")
	if packID == "" {
		deniedEvidence(w)
		return
	}
	read.RequestID = newRequestID()
	flusher, _ := w.(http.Flusher)
	var opened bool
	err := h.evidence.GetPack(r.Context(), read, packID, func(chunk audit.Chunk) error {
		if !opened {
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.Header().Set("Cache-Control", "private, no-store")
			w.WriteHeader(http.StatusOK)
			opened = true
		}
		if err := json.NewEncoder(w).Encode(packChunkView(chunk)); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	})
	if err != nil {
		if opened {
			// The stream already began: a mid-stream failure cannot become a
			// 404, but it must not look like a complete pack either. The
			// consumer sees a truncated stream — nothing of the pack is
			// authoritative until the final chunk arrives (SPEC-0032).
			return
		}
		deniedEvidence(w)
		return
	}
	if !opened {
		// A stream that delivered nothing is the same coarse refusal as
		// everything else.
		deniedEvidence(w)
	}
}

// packChunkView shapes one wire chunk field for field; the adapter adds
// nothing and drops nothing.
func packChunkView(chunk audit.Chunk) PackChunkView {
	view := PackChunkView{ChunkIndex: chunk.ChunkIndex, FinalChunk: chunk.Final}
	if chunk.Header != nil {
		view.Header = &PackHeaderView{
			PackID:       chunk.Header.PackID,
			TenantID:     chunk.Header.TenantID,
			RangeFrom:    chunk.Header.RangeFrom,
			RangeTo:      chunk.Header.RangeTo,
			RepositoryID: chunk.Header.RepositoryID,
			RequestedBy:  chunk.Header.RequestedBy,
			DecisionID:   chunk.Header.DecisionID,
			GeneratedAt:  chunk.Header.GeneratedAt,
		}
	}
	if chunk.Section != nil {
		view.Section = sectionView(*chunk.Section)
	}
	if chunk.Appendix != nil {
		view.Appendix = appendixView(*chunk.Appendix)
	}
	return view
}

func sectionView(section audit.ControlSection) *ControlSectionView {
	view := ControlSectionView{
		Type:          string(section.Type),
		Complete:      section.Complete,
		Gaps:          make([]GapView, 0, len(section.Gaps)),
		Records:       make([]ControlRecordView, 0, len(section.Records)),
		RecordsDigest: section.RecordsDigest,
	}
	if section.Anchors != nil {
		view.Anchors = &AnchorView{
			FirstSeq:        section.Anchors.FirstSeq,
			LastSeq:         section.Anchors.LastSeq,
			FirstRecordHash: section.Anchors.FirstRecordHash,
			LastRecordHash:  section.Anchors.LastRecordHash,
			PrevRecordHash:  section.Anchors.PrevRecordHash,
		}
	}
	for _, gap := range section.Gaps {
		view.Gaps = append(view.Gaps, gapView(gap))
	}
	for _, record := range section.Records {
		shaped := ControlRecordView{
			ChainSeq:   record.ChainSeq,
			RecordHash: record.RecordHash,
			ActorID:    record.ActorID,
			Resource:   record.Resource,
			Action:     record.Action,
			Allowed:    record.Allowed,
			OccurredAt: record.OccurredAt,
		}
		if record.Approval != nil {
			shaped.Approval = &ApprovalView{
				MergeRequestID:   record.Approval.MergeRequestID,
				ProtectionRuleID: record.Approval.ProtectionRuleID,
			}
		}
		if record.PolicyDecision != nil {
			shaped.PolicyDecision = &PolicyDecisionView{
				DecisionID:     record.PolicyDecision.DecisionID,
				BundleRevision: record.PolicyDecision.BundleRevision,
				InputDigest:    record.PolicyDecision.InputDigest,
				Mode:           record.PolicyDecision.Mode,
			}
		}
		if record.ScanGate != nil {
			shaped.ScanGate = &ScanGateView{
				MergeRequestID:      record.ScanGate.MergeRequestID,
				ScanID:              record.ScanGate.ScanID,
				ReliedUponTriageIDs: record.ScanGate.ReliedUponTriageIDs,
			}
		}
		if record.AccessChange != nil {
			shaped.AccessChange = &AccessChangeView{
				AccessKind:        record.AccessChange.AccessKind,
				TargetPrincipalID: record.AccessChange.TargetPrincipalID,
				GrantID:           record.AccessChange.GrantID,
			}
		}
		view.Records = append(view.Records, shaped)
	}
	return &view
}

func appendixView(appendix audit.Appendix) *AppendixView {
	view := AppendixView{Label: appendix.Label, Groups: make([]ImportGroupView, 0, len(appendix.Groups))}
	for _, group := range appendix.Groups {
		shaped := ImportGroupView{Records: make([]AppendixRecordView, 0, len(group.Records))}
		if group.HistoryImported != nil {
			shaped.HistoryImported = &HistoryImportedView{
				EventID:        group.HistoryImported.EventID,
				ActorID:        group.HistoryImported.ActorID,
				RepositoryID:   group.HistoryImported.RepositoryID,
				ImportID:       group.HistoryImported.ImportID,
				SourceSystem:   group.HistoryImported.SourceSystem,
				SourceInstance: group.HistoryImported.SourceInstance,
				RecordCounts:   group.HistoryImported.RecordCounts,
				ManifestDigest: group.HistoryImported.ManifestDigest,
				OccurredAt:     group.HistoryImported.OccurredAt,
			}
		}
		for _, record := range group.Records {
			shapedRecord := AppendixRecordView{
				RecordKind:       record.RecordKind,
				SourceRef:        record.SourceRef,
				Payload:          record.Payload,
				PayloadMediaType: record.PayloadMediaType,
			}
			if record.Provenance != nil {
				shapedRecord.Provenance = &ProvenanceView{
					Class:          record.Provenance.Class,
					ImportID:       record.Provenance.ImportID,
					SourceSystem:   record.Provenance.SourceSystem,
					SourceInstance: record.Provenance.SourceInstance,
					SourceRef:      record.Provenance.SourceRef,
					DeclaredActor:  record.Provenance.DeclaredActor,
					DeclaredAt:     record.Provenance.DeclaredAt,
					PayloadDigest:  record.Provenance.PayloadDigest,
				}
			}
			shaped.Records = append(shaped.Records, shapedRecord)
		}
		view.Groups = append(view.Groups, shaped)
	}
	return &view
}

// deniedEvidence is the one refusal this surface returns: it distinguishes
// nothing about what exists, what is allowed, or why (SPEC-0001).
func deniedEvidence(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	http.Error(w, "evidence unavailable", http.StatusNotFound)
}
