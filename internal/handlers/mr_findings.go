// mr_findings.go is the merge-request findings surface (SPEC-0028, T-0024).
// Findings render inline on the merge request that introduced them: the
// backend FindingsService computes attribution as the set difference between
// the scan at the MR's head revision and the scan at the merge base, under
// server-derived authorization, and this surface forwards the session's
// verified identity and shapes only (SPEC-0028 AC9). A missing, failed or
// timed-out scan reaches the reviewer as UNAVAILABLE with its reason, never
// as an empty page (SPEC-0028 AC7).
package handlers

import (
	"net/http"
	"strconv"

	"github.com/gitfrok/bff/internal/security"
)

// MRFindingLocationView is the finding's location as resolved at the MR's
// current head revision (SPEC-0028 AC4).
type MRFindingLocationView struct {
	ArtifactPath     string `json:"artifact_path"`
	EnclosingContent string `json:"enclosing_content"`
	Component        string `json:"component"`
	ComponentVersion string `json:"component_version"`
}

// MRFindingView is one finding as the merge request renders it: the finding,
// the triage state attached to its identity, its head-revision location, and
// its attribution status. Triage is omitted exactly when no triage decision
// has been recorded — the only meaning of absence here (SPEC-0027).
type MRFindingView struct {
	Finding           FindingView           `json:"finding"`
	Triage            *TriageView           `json:"triage,omitempty"`
	HeadLocation      MRFindingLocationView `json:"head_location"`
	Attribution       string                `json:"attribution"`
	UnavailableReason string                `json:"unavailable_reason,omitempty"`
}

// AttributionSummaryView is the response-level statement of what was
// compared and what the comparison produced. It is always present: the shape
// has no way to say "no findings" without also saying what was compared
// (SPEC-0028 AC7). Counts cover only findings the caller may read.
type AttributionSummaryView struct {
	Status             string `json:"status"`
	UnavailableReason  string `json:"unavailable_reason,omitempty"`
	HeadRevision       string `json:"head_revision"`
	MergeBaseRevision  string `json:"merge_base_revision"`
	Stale              bool   `json:"stale"`
	AttributedLow      int64  `json:"attributed_low"`
	AttributedMedium   int64  `json:"attributed_medium"`
	AttributedHigh     int64  `json:"attributed_high"`
	AttributedCritical int64  `json:"attributed_critical"`
}

// MRFindingsPageView is the JSON shape the MR findings endpoint returns.
// Findings is never null so the empty page marshals identically every time.
type MRFindingsPageView struct {
	Findings      []MRFindingView        `json:"findings"`
	NextPageToken string                 `json:"next_page_token"`
	Summary       AttributionSummaryView `json:"summary"`
}

// mrFindingsQuery reads the MR-findings query from the path and the query
// string with the contract's UNSPECIFIED/empty/zero semantics: an absent
// parameter is no filter, and a filter the contract does not name is the
// same coarse refusal as everything else.
func mrFindingsQuery(r *http.Request) (security.MergeRequestFindingsQuery, bool) {
	query := r.URL.Query()
	pageSize := int32(0)
	if raw := query.Get("page_size"); raw != "" {
		size, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return security.MergeRequestFindingsQuery{}, false
		}
		pageSize = int32(size)
	}
	q := security.MergeRequestFindingsQuery{
		MergeRequestID: r.PathValue("merge_request_id"),
		ScannerClass:   query.Get("scanner_class"),
		Severity:       query.Get("severity"),
		Attribution:    query.Get("attribution"),
		PageSize:       pageSize,
		PageToken:      query.Get("page_token"),
	}
	// A missing merge-request identity or a filter the contract does not
	// name is refused here, before anything reaches the backend — the same
	// coarse shape as every other refusal.
	return q, security.ValidateMRFindingsQuery(q)
}

// mrFindings pages the findings a merge request introduced. The merge
// request reaches this surface only as the opaque identifier the path names:
// no head revision, no merge base and no authorization outcome is
// caller-assertable — all of those are server facts (SPEC-0028).
func (h *SecurityHandler) mrFindings(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedSecurity(w)
		return
	}
	q, ok := mrFindingsQuery(r)
	if !ok {
		deniedSecurity(w)
		return
	}
	read.RequestID = newRequestID()
	page, err := h.security.ListMergeRequestFindings(r.Context(), read, q)
	if err != nil {
		deniedSecurity(w)
		return
	}
	writeJSON(w, mrFindingsView(page))
}

// mrFindingsView shapes the authorized page field for field: membership,
// order, attribution and counts come from the backend untouched.
func mrFindingsView(page security.MergeRequestFindingsPage) MRFindingsPageView {
	view := MRFindingsPageView{
		Findings:      make([]MRFindingView, 0, len(page.Findings)),
		NextPageToken: page.NextPageToken,
		Summary: AttributionSummaryView{
			Status:             page.Summary.Status,
			UnavailableReason:  page.Summary.UnavailableReason,
			HeadRevision:       page.Summary.HeadRevision,
			MergeBaseRevision:  page.Summary.MergeBaseRevision,
			Stale:              page.Summary.Stale,
			AttributedLow:      page.Summary.AttributedLow,
			AttributedMedium:   page.Summary.AttributedMedium,
			AttributedHigh:     page.Summary.AttributedHigh,
			AttributedCritical: page.Summary.AttributedCritical,
		},
	}
	for _, f := range page.Findings {
		shaped := MRFindingView{
			Finding: FindingView{
				FindingID:           f.Finding.FindingID,
				RepositoryID:        f.Finding.RepositoryID,
				ScannerClass:        f.Finding.ScannerClass,
				ToolName:            f.Finding.ToolName,
				ToolVersion:         f.Finding.ToolVersion,
				RuleID:              f.Finding.RuleID,
				Severity:            f.Finding.Severity,
				Lifecycle:           f.Finding.Lifecycle,
				ArtifactPath:        f.Finding.ArtifactPath,
				EnclosingContent:    f.Finding.EnclosingContent,
				Component:           f.Finding.Component,
				ComponentVersion:    f.Finding.ComponentVersion,
				FirstSeenScanID:     f.Finding.FirstSeenScanID,
				LastSeenScanID:      f.Finding.LastSeenScanID,
				Provenance:          f.Finding.Provenance,
				ProvenanceMediaType: f.Finding.ProvenanceMediaType,
			},
			HeadLocation: MRFindingLocationView{
				ArtifactPath:     f.HeadArtifactPath,
				EnclosingContent: f.HeadEnclosingContent,
				Component:        f.HeadComponent,
				ComponentVersion: f.HeadComponentVersion,
			},
			Attribution:       f.Attribution,
			UnavailableReason: f.UnavailableReason,
		}
		if f.Triage != nil {
			shaped.Triage = &TriageView{
				TriageID:      f.Triage.TriageID,
				FindingID:     f.Triage.FindingID,
				RepositoryID:  f.Triage.RepositoryID,
				State:         string(f.Triage.State),
				Justification: f.Triage.Justification,
				Version:       f.Triage.Version,
				ActorID:       f.Triage.ActorID,
				OccurredAt:    f.Triage.OccurredAt,
			}
		}
		view.Findings = append(view.Findings, shaped)
	}
	return view
}
