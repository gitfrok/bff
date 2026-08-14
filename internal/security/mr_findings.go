// mr_findings.go adapts ListMergeRequestFindings — the findings a merge
// request introduced (SPEC-0028, T-0024) — onto BFF-shaped types. The
// backend computes attribution as the set difference between the scan at the
// MR's head revision and the scan at the merge base; this adapter carries
// verified identity and shapes only. A missing, failed or timed-out scan is
// UNAVAILABLE with a reason here, never an empty page (SPEC-0028 AC7).
package security

import (
	"context"

	securityv1 "github.com/gitfrok/bff/gen/proto/security/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

// Attribution names the attribution vocabulary a merge-request finding view
// carries (SPEC-0028). It is server-derived state: a request may filter by
// it, but no request can assert it.
type Attribution string

const (
	// AttributionAttributed: present at the MR's head revision and absent at
	// the merge base — the merge request introduced it.
	AttributionAttributed Attribution = "ATTRIBUTED"
	// AttributionPreExisting: present at both head and merge base — it
	// predates the merge request and is never attributed to it.
	AttributionPreExisting Attribution = "PRE_EXISTING"
	// AttributionUnavailable: the comparison cannot be computed; the reason
	// travels with it, never an empty result set.
	AttributionUnavailable Attribution = "UNAVAILABLE"
)

// wireAttribution maps a filter name onto the contract enum with the same
// empty/unnamed semantics as wireScannerClass: empty is no filter, an
// unnamed name is ErrMalformed.
func wireAttribution(name string) (securityv1.AttributionStatus, error) {
	switch name {
	case "":
		return securityv1.AttributionStatus_ATTRIBUTION_STATUS_UNSPECIFIED, nil
	case string(AttributionAttributed):
		return securityv1.AttributionStatus_ATTRIBUTION_STATUS_ATTRIBUTED, nil
	case string(AttributionPreExisting):
		return securityv1.AttributionStatus_ATTRIBUTION_STATUS_PRE_EXISTING, nil
	case string(AttributionUnavailable):
		return securityv1.AttributionStatus_ATTRIBUTION_STATUS_UNAVAILABLE, nil
	default:
		return securityv1.AttributionStatus_ATTRIBUTION_STATUS_UNSPECIFIED, ErrMalformed
	}
}

func attributionName(wire securityv1.AttributionStatus) string {
	switch wire {
	case securityv1.AttributionStatus_ATTRIBUTION_STATUS_ATTRIBUTED:
		return string(AttributionAttributed)
	case securityv1.AttributionStatus_ATTRIBUTION_STATUS_PRE_EXISTING:
		return string(AttributionPreExisting)
	case securityv1.AttributionStatus_ATTRIBUTION_STATUS_UNAVAILABLE:
		return string(AttributionUnavailable)
	default:
		return ""
	}
}

// attributionReasonName renders the honest reason an attribution is
// UNAVAILABLE — never source, never an empty set standing in for it
// (SPEC-0028 AC7).
func attributionReasonName(wire securityv1.AttributionUnavailableReason) string {
	switch wire {
	case securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_BASE_NOT_SCANNED:
		return "BASE_NOT_SCANNED"
	case securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_HEAD_SCAN_FAILED:
		return "HEAD_SCAN_FAILED"
	case securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_HEAD_SCAN_TIMED_OUT:
		return "HEAD_SCAN_TIMED_OUT"
	case securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_HEAD_SCAN_NOT_RUN:
		return "HEAD_SCAN_NOT_RUN"
	case securityv1.AttributionUnavailableReason_ATTRIBUTION_UNAVAILABLE_REASON_NO_MERGE_BASE:
		return "NO_MERGE_BASE"
	default:
		return ""
	}
}

// MergeRequestFindingsQuery is one MR-findings read. MergeRequestID is the
// opaque, Code Review-assigned identity; the contract gives the request no
// head revision, no merge base and no authorization outcome to carry
// (SPEC-0028). The filters carry the contract's UNSPECIFIED/empty/zero
// semantics: the zero value is no filter, and which findings survive is the
// backend's decision alone.
type MergeRequestFindingsQuery struct {
	MergeRequestID string
	ScannerClass   string
	Severity       string
	Attribution    string
	PageSize       int32
	PageToken      string
}

// ValidateMRFindingsQuery reports whether every named filter is one the
// contract defines and the merge-request identity is present. The HTTP
// surface uses it to refuse an unnamed filter before anything reaches the
// backend; the adapter enforces the same rule on the wire.
func ValidateMRFindingsQuery(q MergeRequestFindingsQuery) bool {
	if q.MergeRequestID == "" {
		return false
	}
	_, _, _, err := mrFilterEnums(q)
	return err == nil
}

// mrFilterEnums maps the named MR-findings filters onto their contract
// enums; an unnamed name is ErrMalformed.
func mrFilterEnums(q MergeRequestFindingsQuery) (securityv1.ScannerClass, securityv1.FindingSeverity, securityv1.AttributionStatus, error) {
	scannerClass, err := wireScannerClass(q.ScannerClass)
	if err != nil {
		return 0, 0, 0, err
	}
	severity, err := wireSeverity(q.Severity)
	if err != nil {
		return 0, 0, 0, err
	}
	attribution, err := wireAttribution(q.Attribution)
	if err != nil {
		return 0, 0, 0, err
	}
	return scannerClass, severity, attribution, nil
}

// MergeRequestFinding is one finding as it renders on the merge request
// under review: the finding, the triage state attached to its identity, its
// location resolved at the MR's head revision, and its attribution status
// (SPEC-0028). Triage is nil exactly when no triage decision has been
// recorded — the only meaning of absence here.
type MergeRequestFinding struct {
	Finding Finding
	Triage  *Triage
	// HeadLocation, resolved at the MR's current head revision: identity is
	// revision-invariant (SPEC-0024), so a later push that shifts the line
	// re-resolves these fields without changing the finding they belong to.
	HeadArtifactPath     string
	HeadEnclosingContent string
	HeadComponent        string
	HeadComponentVersion string
	Attribution          string
	// UnavailableReason is set only when Attribution is UNAVAILABLE.
	UnavailableReason string
}

// AttributionSummary is the response-level statement of what was compared
// and what the comparison produced. It is always present: the shape has no
// way to say "no findings" without also saying what was compared
// (SPEC-0028 AC7). Counts cover only findings the caller may read.
type AttributionSummary struct {
	Status             string
	UnavailableReason  string
	HeadRevision       string
	MergeBaseRevision  string
	Stale              bool
	AttributedLow      int64
	AttributedMedium   int64
	AttributedHigh     int64
	AttributedCritical int64
}

// MergeRequestFindingsPage is one authorized MR-findings page. An empty
// Findings slice is a legitimate answer only when the summary says
// attribution was computed and found nothing; an UNAVAILABLE summary with an
// empty page is still UNAVAILABLE (SPEC-0028 AC7).
type MergeRequestFindingsPage struct {
	Findings      []MergeRequestFinding
	NextPageToken string
	Summary       AttributionSummary
}

// ListMergeRequestFindings pages the findings attributable to one merge
// request under the session's verified identity. Membership, order,
// attribution and counts come from the backend untouched; an unnamed filter
// or a missing merge-request identity is ErrMalformed before anything
// crosses the wire.
func (c *Client) ListMergeRequestFindings(ctx context.Context, read aggregate.ReadContext, q MergeRequestFindingsQuery) (MergeRequestFindingsPage, error) {
	if q.MergeRequestID == "" {
		return MergeRequestFindingsPage{}, ErrMalformed
	}
	scannerClass, severity, attribution, err := mrFilterEnums(q)
	if err != nil {
		return MergeRequestFindingsPage{}, err
	}
	response, err := c.service.ListMergeRequestFindings(ctx, &securityv1.ListMergeRequestFindingsRequest{
		Context:            contextOf(read),
		MergeRequestId:     q.MergeRequestID,
		ScannerClassFilter: scannerClass,
		SeverityFilter:     severity,
		AttributionFilter:  attribution,
		PageSize:           q.PageSize,
		PageToken:          q.PageToken,
	})
	if err != nil {
		return MergeRequestFindingsPage{}, err
	}
	page := MergeRequestFindingsPage{
		Findings:      make([]MergeRequestFinding, 0, len(response.GetFindings())),
		NextPageToken: response.GetNextPageToken(),
		Summary:       shapeAttributionSummary(response.GetSummary()),
	}
	for _, view := range response.GetFindings() {
		page.Findings = append(page.Findings, shapeMergeRequestFinding(view))
	}
	return page, nil
}

func shapeMergeRequestFinding(view *securityv1.MergeRequestFindingView) MergeRequestFinding {
	finding := MergeRequestFinding{
		Finding:           shapeFinding(view.GetFinding()),
		Attribution:       attributionName(view.GetAttribution()),
		UnavailableReason: attributionReasonName(view.GetUnavailableReason()),
	}
	if triage := view.GetTriage(); triage != nil {
		record := shapeTriage(triage)
		finding.Triage = &record
	}
	if loc := view.GetHeadLocation(); loc != nil {
		finding.HeadArtifactPath = loc.GetArtifactPath()
		finding.HeadEnclosingContent = loc.GetEnclosingContent()
		finding.HeadComponent = loc.GetComponent()
		finding.HeadComponentVersion = loc.GetComponentVersion()
	}
	return finding
}

func shapeAttributionSummary(summary *securityv1.AttributionSummary) AttributionSummary {
	return AttributionSummary{
		Status:             attributionName(summary.GetStatus()),
		UnavailableReason:  attributionReasonName(summary.GetUnavailableReason()),
		HeadRevision:       summary.GetHeadRevision(),
		MergeBaseRevision:  summary.GetMergeBaseRevision(),
		Stale:              summary.GetStale(),
		AttributedLow:      summary.GetAttributedLow(),
		AttributedMedium:   summary.GetAttributedMedium(),
		AttributedHigh:     summary.GetAttributedHigh(),
		AttributedCritical: summary.GetAttributedCritical(),
	}
}
