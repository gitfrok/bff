// Package security adapts the generated FindingsService gRPC client onto
// BFF-shaped request/response types. It carries verified identity and shapes
// only (SPEC-0026, SPEC-0027, T-0023): the backend is the PDP for
// findings.triage, findings.read and findings.summary.read, the caller's
// readable repository set is derived server-side inside each query, and
// nothing here filters, aggregates, or authorizes (invariant 18).
package security

import (
	"context"
	"errors"
	"time"

	securityv1 "github.com/gitfrok/bff/gen/proto/security/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

// ErrMalformed refuses a request whose shape the contract does not name. It
// is coarse: the caller learns nothing about what exists or what is allowed.
var ErrMalformed = errors.New("security: malformed request")

// TriageState names the decision vocabulary a triage record carries
// (SPEC-0026). UNSPECIFIED is not a state a record can hold: clearing a
// decision is not a v1 operation, so an unnamed state is ErrMalformed, not
// a default (SPEC-0026 AC5).
type TriageState string

const (
	TriageAccept        TriageState = "ACCEPT"
	TriageFalsePositive TriageState = "FALSE_POSITIVE"
	TriageFix           TriageState = "FIX"
	TriageDefer         TriageState = "DEFER"
	wireTriageAccept                = securityv1.TriageState_TRIAGE_STATE_ACCEPT
	wireTriageFalsePos              = securityv1.TriageState_TRIAGE_STATE_FALSE_POSITIVE
	wireTriageFix                   = securityv1.TriageState_TRIAGE_STATE_FIX
	wireTriageDefer                 = securityv1.TriageState_TRIAGE_STATE_DEFER
)

// StateOf maps the wire name onto the contract enum. The second result is
// false for anything the contract does not name as a recordable decision.
func StateOf(name string) (TriageState, bool) {
	switch TriageState(name) {
	case TriageAccept, TriageFalsePositive, TriageFix, TriageDefer:
		return TriageState(name), true
	default:
		return "", false
	}
}

func wireState(state TriageState) (securityv1.TriageState, bool) {
	switch state {
	case TriageAccept:
		return wireTriageAccept, true
	case TriageFalsePositive:
		return wireTriageFalsePos, true
	case TriageFix:
		return wireTriageFix, true
	case TriageDefer:
		return wireTriageDefer, true
	default:
		return securityv1.TriageState_TRIAGE_STATE_UNSPECIFIED, false
	}
}

func stateOf(wire securityv1.TriageState) TriageState {
	switch wire {
	case securityv1.TriageState_TRIAGE_STATE_ACCEPT:
		return TriageAccept
	case securityv1.TriageState_TRIAGE_STATE_FALSE_POSITIVE:
		return TriageFalsePositive
	case securityv1.TriageState_TRIAGE_STATE_FIX:
		return TriageFix
	case securityv1.TriageState_TRIAGE_STATE_DEFER:
		return TriageDefer
	default:
		return ""
	}
}

// Filters is the dashboard filter set (SPEC-0026 AC2). Every field mirrors
// the contract's UNSPECIFIED/empty/zero semantics: the zero value is no
// filter, and which findings survive is the backend's decision alone.
type Filters struct {
	Repository   string
	ScannerClass string
	Severity     string
	Lifecycle    string
	MinAgeDays   int32
	MaxAgeDays   int32
	OwningTeam   string
}

// Finding is one authorized finding, shaped for the browser. It carries
// opaque identifiers and normalized values only — no permission fact.
type Finding struct {
	FindingID           string
	RepositoryID        string
	ScannerClass        string
	ToolName            string
	ToolVersion         string
	RuleID              string
	Severity            string
	Lifecycle           string
	ArtifactPath        string
	EnclosingContent    string
	Component           string
	ComponentVersion    string
	FirstSeenScanID     string
	LastSeenScanID      string
	Provenance          []byte
	ProvenanceMediaType string
}

// FindingPage is one authorized list page. It has no total: a count the
// caller may not read has no field to travel in (SPEC-0026 AC6).
type FindingPage struct {
	Findings      []Finding
	NextPageToken string
}

// Triage is one triage decision attached to a finding identity — a resource
// of its own, never a field of the finding (SPEC-0027).
type Triage struct {
	TriageID      string
	FindingID     string
	RepositoryID  string
	State         TriageState
	Justification string
	Version       int64
	ActorID       string
	OccurredAt    time.Time
}

// TriageRequest records one decision. It carries no severity, no lifecycle
// state and no authorization flag: the contract has no fields for them, so a
// request cannot assert them (SPEC-0027). ExpectedVersion is the version
// last read; zero expects no record at all.
type TriageRequest struct {
	FindingID       string
	State           TriageState
	Justification   string
	ExpectedVersion int64
}

// Summary is the dashboard's authorized counts and facets. Total counts only
// findings the caller may read; a facet value existing only in a repository
// the caller may not read is absent, not zero (SPEC-0027 AC4).
type Summary struct {
	TotalCount int64
	Facets     []Facet
}

// Facet is one requested dimension's authorized distribution.
type Facet struct {
	Dimension string
	Values    []FacetValue
}

// FacetValue is one value within a facet and the count of authorized
// findings carrying it.
type FacetValue struct {
	Value string
	Count int64
}

// Client talks to the backend's FindingsService.
type Client struct {
	service securityv1.FindingsServiceClient
}

// New wires the adapter onto the generated client.
func New(service securityv1.FindingsServiceClient) *Client {
	return &Client{service: service}
}

// contextOf maps the verified session identity onto the wire context. The
// readable repository set is server-derived, never caller-supplied: the
// context names no scope a request could forge (SPEC-0026 AC6).
func contextOf(read aggregate.ReadContext) *securityv1.FindingsContext {
	return &securityv1.FindingsContext{
		TenantId:   read.TenantID,
		ActorId:    read.ActorID,
		ActorRoles: append([]string(nil), read.ActorRoles...),
		RequestId:  read.RequestID,
	}
}

// wireScannerClass maps a filter name onto the contract enum. Empty is no
// filter; anything the contract does not name is ErrMalformed, not a
// default (SPEC-0024 AC1).
func wireScannerClass(name string) (securityv1.ScannerClass, error) {
	switch name {
	case "":
		return securityv1.ScannerClass_SCANNER_CLASS_UNSPECIFIED, nil
	case "SAST":
		return securityv1.ScannerClass_SCANNER_CLASS_SAST, nil
	case "DEPENDENCY":
		return securityv1.ScannerClass_SCANNER_CLASS_DEPENDENCY, nil
	case "SECRETS":
		return securityv1.ScannerClass_SCANNER_CLASS_SECRETS, nil
	case "CONTAINER":
		return securityv1.ScannerClass_SCANNER_CLASS_CONTAINER, nil
	case "DAST":
		return securityv1.ScannerClass_SCANNER_CLASS_DAST, nil
	default:
		return securityv1.ScannerClass_SCANNER_CLASS_UNSPECIFIED, ErrMalformed
	}
}

func scannerClassName(wire securityv1.ScannerClass) string {
	switch wire {
	case securityv1.ScannerClass_SCANNER_CLASS_SAST:
		return "SAST"
	case securityv1.ScannerClass_SCANNER_CLASS_DEPENDENCY:
		return "DEPENDENCY"
	case securityv1.ScannerClass_SCANNER_CLASS_SECRETS:
		return "SECRETS"
	case securityv1.ScannerClass_SCANNER_CLASS_CONTAINER:
		return "CONTAINER"
	case securityv1.ScannerClass_SCANNER_CLASS_DAST:
		return "DAST"
	default:
		return ""
	}
}

// wireSeverity maps a filter name onto the contract enum with the same
// empty/unnamed semantics as wireScannerClass.
func wireSeverity(name string) (securityv1.FindingSeverity, error) {
	switch name {
	case "":
		return securityv1.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED, nil
	case "LOW":
		return securityv1.FindingSeverity_FINDING_SEVERITY_LOW, nil
	case "MEDIUM":
		return securityv1.FindingSeverity_FINDING_SEVERITY_MEDIUM, nil
	case "HIGH":
		return securityv1.FindingSeverity_FINDING_SEVERITY_HIGH, nil
	case "CRITICAL":
		return securityv1.FindingSeverity_FINDING_SEVERITY_CRITICAL, nil
	default:
		return securityv1.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED, ErrMalformed
	}
}

func severityName(wire securityv1.FindingSeverity) string {
	switch wire {
	case securityv1.FindingSeverity_FINDING_SEVERITY_LOW:
		return "LOW"
	case securityv1.FindingSeverity_FINDING_SEVERITY_MEDIUM:
		return "MEDIUM"
	case securityv1.FindingSeverity_FINDING_SEVERITY_HIGH:
		return "HIGH"
	case securityv1.FindingSeverity_FINDING_SEVERITY_CRITICAL:
		return "CRITICAL"
	default:
		return ""
	}
}

// wireLifecycle maps a filter name onto the contract enum with the same
// empty/unnamed semantics. A lifecycle value is server state: it is a filter
// the dashboard may ask with, never a value a request may set.
func wireLifecycle(name string) (securityv1.FindingLifecycle, error) {
	switch name {
	case "":
		return securityv1.FindingLifecycle_FINDING_LIFECYCLE_UNSPECIFIED, nil
	case "OPEN":
		return securityv1.FindingLifecycle_FINDING_LIFECYCLE_OPEN, nil
	case "RESOLVED":
		return securityv1.FindingLifecycle_FINDING_LIFECYCLE_RESOLVED, nil
	default:
		return securityv1.FindingLifecycle_FINDING_LIFECYCLE_UNSPECIFIED, ErrMalformed
	}
}

func lifecycleName(wire securityv1.FindingLifecycle) string {
	switch wire {
	case securityv1.FindingLifecycle_FINDING_LIFECYCLE_OPEN:
		return "OPEN"
	case securityv1.FindingLifecycle_FINDING_LIFECYCLE_RESOLVED:
		return "RESOLVED"
	default:
		return ""
	}
}

// SetTriage records one triage decision under the session's verified
// identity and returns the record now in force — the one this request
// wrote, or the one already there on a replayed request ID or a version
// mismatch (SPEC-0027 AC1).
func (c *Client) SetTriage(ctx context.Context, read aggregate.ReadContext, in TriageRequest) (Triage, error) {
	state, ok := wireState(in.State)
	if !ok {
		return Triage{}, ErrMalformed
	}
	response, err := c.service.SetTriage(ctx, &securityv1.SetTriageRequest{
		Context:         contextOf(read),
		FindingId:       in.FindingID,
		State:           state,
		Justification:   in.Justification,
		ExpectedVersion: in.ExpectedVersion,
	})
	if err != nil {
		return Triage{}, err
	}
	return shapeTriage(response.GetRecord()), nil
}

func shapeTriage(record *securityv1.TriageRecord) Triage {
	triage := Triage{
		TriageID:      record.GetTriageId(),
		FindingID:     record.GetFindingId(),
		RepositoryID:  record.GetRepositoryId(),
		State:         stateOf(record.GetState()),
		Justification: record.GetJustification(),
		Version:       record.GetVersion(),
		ActorID:       record.GetActorId(),
	}
	if t := record.GetOccurredAt(); t != nil {
		triage.OccurredAt = t.AsTime()
	}
	return triage
}

// ListFindings pages the caller's authorized findings under the dashboard
// filter set. Membership and order come from the backend untouched; a
// repository the caller may not read contributes no finding and no cursor
// hint (SPEC-0026 AC6).
func (c *Client) ListFindings(ctx context.Context, read aggregate.ReadContext, f Filters, pageSize int32, pageToken string) (FindingPage, error) {
	request, err := listRequest(read, f, pageSize, pageToken)
	if err != nil {
		return FindingPage{}, err
	}
	response, err := c.service.ListFindings(ctx, request)
	if err != nil {
		return FindingPage{}, err
	}
	page := FindingPage{Findings: make([]Finding, 0, len(response.GetFindings())), NextPageToken: response.GetNextPageToken()}
	for _, m := range response.GetFindings() {
		finding := Finding{
			FindingID:           m.GetFindingId(),
			RepositoryID:        m.GetRepositoryId(),
			ScannerClass:        scannerClassName(m.GetScannerClass()),
			ToolName:            m.GetToolName(),
			ToolVersion:         m.GetToolVersion(),
			RuleID:              m.GetRuleId(),
			Severity:            severityName(m.GetSeverity()),
			Lifecycle:           lifecycleName(m.GetLifecycle()),
			FirstSeenScanID:     m.GetFirstSeenScanId(),
			LastSeenScanID:      m.GetLastSeenScanId(),
			Provenance:          m.GetProvenance(),
			ProvenanceMediaType: m.GetProvenanceMediaType(),
		}
		if loc := m.GetLocation(); loc != nil {
			finding.ArtifactPath = loc.GetArtifactPath()
			finding.EnclosingContent = loc.GetEnclosingContent()
			finding.Component = loc.GetComponent()
			finding.ComponentVersion = loc.GetComponentVersion()
		}
		page.Findings = append(page.Findings, finding)
	}
	return page, nil
}

// ValidateFilters reports whether every named filter is one the contract
// defines, the empty/zero values carrying their no-filter meaning. The HTTP
// surface uses it to refuse an unnamed filter before anything reaches the
// backend; the wire mappers below enforce the same rule.
func ValidateFilters(f Filters) bool {
	_, _, _, err := filterEnums(f)
	return err == nil
}

// filterEnums maps the named filters onto their contract enums; an unnamed
// name is ErrMalformed.
func filterEnums(f Filters) (securityv1.ScannerClass, securityv1.FindingSeverity, securityv1.FindingLifecycle, error) {
	scannerClass, err := wireScannerClass(f.ScannerClass)
	if err != nil {
		return 0, 0, 0, err
	}
	severity, err := wireSeverity(f.Severity)
	if err != nil {
		return 0, 0, 0, err
	}
	lifecycle, err := wireLifecycle(f.Lifecycle)
	if err != nil {
		return 0, 0, 0, err
	}
	return scannerClass, severity, lifecycle, nil
}

// listRequest builds the shared filter half of the dashboard reads. Filter
// names the contract does not define are ErrMalformed before anything
// crosses the wire.
func listRequest(read aggregate.ReadContext, f Filters, pageSize int32, pageToken string) (*securityv1.ListFindingsRequest, error) {
	scannerClass, severity, lifecycle, err := filterEnums(f)
	if err != nil {
		return nil, err
	}
	return &securityv1.ListFindingsRequest{
		Context:            contextOf(read),
		RepositoryFilter:   f.Repository,
		ScannerClassFilter: scannerClass,
		SeverityFilter:     severity,
		LifecycleFilter:    lifecycle,
		PageSize:           pageSize,
		PageToken:          pageToken,
		MinAgeDays:         f.MinAgeDays,
		MaxAgeDays:         f.MaxAgeDays,
		OwningTeamFilter:   f.OwningTeam,
	}, nil
}

// FindingsSummary returns counts and facet values computed under the
// caller's authorization — the authorization filter is part of the query,
// never a mask applied late (SPEC-0026 AC6, SPEC-0027 AC4). Dimensions is
// forwarded untouched: which dimensions are known is the backend's decision.
func (c *Client) FindingsSummary(ctx context.Context, read aggregate.ReadContext, f Filters, dimensions []string) (Summary, error) {
	scannerClass, severity, lifecycle, err := filterEnums(f)
	if err != nil {
		return Summary{}, err
	}
	response, err := c.service.GetFindingsSummary(ctx, &securityv1.GetFindingsSummaryRequest{
		Context:            contextOf(read),
		RepositoryFilter:   f.Repository,
		ScannerClassFilter: scannerClass,
		SeverityFilter:     severity,
		LifecycleFilter:    lifecycle,
		MinAgeDays:         f.MinAgeDays,
		MaxAgeDays:         f.MaxAgeDays,
		OwningTeamFilter:   f.OwningTeam,
		FacetDimensions:    append([]string(nil), dimensions...),
	})
	if err != nil {
		return Summary{}, err
	}
	summary := Summary{TotalCount: response.GetTotalCount(), Facets: make([]Facet, 0, len(response.GetFacets()))}
	for _, facet := range response.GetFacets() {
		shaped := Facet{Dimension: facet.GetDimension(), Values: make([]FacetValue, 0, len(facet.GetValues()))}
		for _, value := range facet.GetValues() {
			shaped.Values = append(shaped.Values, FacetValue{Value: value.GetValue(), Count: value.GetCount()})
		}
		summary.Facets = append(summary.Facets, shaped)
	}
	return summary, nil
}
