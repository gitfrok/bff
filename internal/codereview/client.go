// Package codereview adapts the generated MergeRequestService gRPC client onto
// BFF-shaped request/response types. It shapes and forwards; the backend owns
// every decision (SPEC-0019, invariant 18).
package codereview

import (
	"context"
	"time"

	codereviewv1 "github.com/gitfrok/bff/gen/proto/codereview/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

// Client talks to the backend's MergeRequestService.
type Client struct {
	service codereviewv1.MergeRequestServiceClient
}

// New wires the adapter onto the generated client.
func New(service codereviewv1.MergeRequestServiceClient) *Client {
	return &Client{service: service}
}

// MergeRequest is the shaped review state the browser consumes.
type MergeRequest struct {
	MergeRequestID string
	RepositoryID   string
	SourceRef      string
	TargetRef      string
	Title          string
	Description    string
	CreatorID      string
	State          string
	HeadRevision   string
	Version        int64
	CreatedAt      time.Time
	// ExternalIssues are references to issues in the customer's own tracker
	// (SPEC-0059). Pointers, not copies: there is no title and no state here,
	// because nothing in this product asks the tracker anything.
	ExternalIssues []ExternalIssue
}

// ExternalIssue is one reference to an issue this product does not store.
//
// URL is what a reader clicks. The frontend renders it only when it is https —
// refused in the backend's domain and refused again there, because a link a person
// clicks from inside the product is worth refusing twice.
type ExternalIssue struct {
	Tracker  string
	IssueKey string
	URL      string
	LinkedBy string
	LinkedAt string
}

// ReviewContext is the verified identity the backend's ReviewCommandContext
// requires. It comes only from the session.
type ReviewContext struct {
	TenantID     string
	RepositoryID string
	ActorID      string
	ActorRoles   []string
	RequestID    string
}

func (c *Client) contextOf(read aggregate.ReadContext) *codereviewv1.ReviewCommandContext {
	return &codereviewv1.ReviewCommandContext{
		TenantId:     read.TenantID,
		RepositoryId: read.RepositoryID,
		ActorId:      read.ActorID,
		ActorRoles:   read.ActorRoles,
		RequestId:    read.RequestID,
	}
}

// Create opens a merge request, optionally as a draft (ADR-0087, SPEC-0064).
func (c *Client) Create(ctx context.Context, read aggregate.ReadContext, sourceRef, targetRef, title, description string, draft bool) (*MergeRequest, error) {
	response, err := c.service.CreateMergeRequest(ctx, &codereviewv1.CreateMergeRequestRequest{
		Context:     c.contextOf(read),
		SourceRef:   sourceRef,
		TargetRef:   targetRef,
		Title:       title,
		Description: description,
		Draft:       draft,
	})
	if err != nil {
		return nil, err
	}
	return shape(response.GetMergeRequest()), nil
}

// Get returns one merge request.
func (c *Client) Get(ctx context.Context, read aggregate.ReadContext, mergeRequestID string) (*MergeRequest, error) {
	response, err := c.service.GetMergeRequest(ctx, &codereviewv1.GetMergeRequestRequest{
		Context:        c.contextOf(read),
		MergeRequestId: mergeRequestID,
	})
	if err != nil {
		return nil, err
	}
	return shape(response.GetMergeRequest()), nil
}

// SubmitReview records a review disposition on an MR.
func (c *Client) SubmitReview(ctx context.Context, read aggregate.ReadContext, mergeRequestID, disposition, comment, headRevision string, expectedVersion int64) (*MergeRequest, error) {
	response, err := c.service.SubmitReview(ctx, &codereviewv1.SubmitReviewRequest{
		Context:         c.contextOf(read),
		MergeRequestId:  mergeRequestID,
		Disposition:     codereviewv1.ReviewDisposition(codereviewv1.ReviewDisposition_value[disposition]),
		Comment:         comment,
		HeadRevision:    headRevision,
		ExpectedVersion: expectedVersion,
	})
	if err != nil {
		return nil, err
	}
	return shape(response.GetMergeRequest()), nil
}

// Merge completes a merge request through the backend's Repository/Git path.
func (c *Client) Merge(ctx context.Context, read aggregate.ReadContext, mergeRequestID string, expectedVersion int64) (*MergeRequest, error) {
	response, err := c.service.MergeMergeRequest(ctx, &codereviewv1.MergeMergeRequestRequest{
		Context:         c.contextOf(read),
		MergeRequestId:  mergeRequestID,
		ExpectedVersion: expectedVersion,
	})
	if err != nil {
		return nil, err
	}
	return shape(response.GetMergeRequest()), nil
}

// MarkReady moves a DRAFT merge request to OPEN (ADR-0087, SPEC-0064). Pure
// passthrough: the draft state machine is the backend's decision entirely.
func (c *Client) MarkReady(ctx context.Context, read aggregate.ReadContext, mergeRequestID string, expectedVersion int64) (*MergeRequest, error) {
	response, err := c.service.MarkMergeRequestReady(ctx, &codereviewv1.MarkMergeRequestReadyRequest{
		Context:         c.contextOf(read),
		MergeRequestId:  mergeRequestID,
		ExpectedVersion: expectedVersion,
	})
	if err != nil {
		return nil, err
	}
	return shape(response.GetMergeRequest()), nil
}

// LinkExternalIssue references an issue that lives in the customer's tracker.
//
// Nothing here validates the URL beyond forwarding it: the backend's domain is the
// authority on what may be stored, and a second opinion at this layer would be a
// second place the rule lives. What this layer does do is keep the refusal legible —
// see the handler's mapping of InvalidArgument.
func (c *Client) LinkExternalIssue(ctx context.Context, read aggregate.ReadContext, mergeRequestID, tracker, issueKey, issueURL string) (*MergeRequest, error) {
	response, err := c.service.LinkExternalIssue(ctx, &codereviewv1.LinkExternalIssueRequest{
		Context:        c.contextOf(read),
		MergeRequestId: mergeRequestID,
		Tracker:        tracker,
		IssueKey:       issueKey,
		Url:            issueURL,
	})
	if err != nil {
		return nil, err
	}
	return shape(response.GetMergeRequest()), nil
}

// UnlinkExternalIssue removes a reference by tracker and key — its identity, never a
// position in a list.
func (c *Client) UnlinkExternalIssue(ctx context.Context, read aggregate.ReadContext, mergeRequestID, tracker, issueKey string) (*MergeRequest, error) {
	response, err := c.service.UnlinkExternalIssue(ctx, &codereviewv1.UnlinkExternalIssueRequest{
		Context:        c.contextOf(read),
		MergeRequestId: mergeRequestID,
		Tracker:        tracker,
		IssueKey:       issueKey,
	})
	if err != nil {
		return nil, err
	}
	return shape(response.GetMergeRequest()), nil
}

// shapeExternalIssues shapes the references. There is no field here that could carry
// what an issue says: check 18 keeps the wire free of one.
func shapeExternalIssues(references []*codereviewv1.ExternalIssue) []ExternalIssue {
	if len(references) == 0 {
		return nil
	}
	out := make([]ExternalIssue, 0, len(references))
	for _, reference := range references {
		out = append(out, ExternalIssue{
			Tracker:  reference.GetTracker(),
			IssueKey: reference.GetIssueKey(),
			URL:      reference.GetUrl(),
			LinkedBy: reference.GetLinkedBy(),
			LinkedAt: reference.GetLinkedAt(),
		})
	}
	return out
}

// SetProtection replaces the exact-ref branch protection rule.
func (c *Client) SetProtection(ctx context.Context, read aggregate.ReadContext, targetRef string, requiredApprovals int32, expectedVersion int64) error {
	_, err := c.service.SetBranchProtection(ctx, &codereviewv1.SetBranchProtectionRequest{
		Context:           c.contextOf(read),
		TargetRef:         targetRef,
		RequiredApprovals: requiredApprovals,
		ExpectedVersion:   expectedVersion,
	})
	return err
}

func shape(mr *codereviewv1.MergeRequest) *MergeRequest {
	if mr == nil {
		return nil
	}
	created := time.Time{}
	if t := mr.GetCreatedAt(); t != nil {
		created = t.AsTime()
	}
	return &MergeRequest{
		MergeRequestID: mr.GetMergeRequestId(),
		RepositoryID:   mr.GetRepositoryId(),
		SourceRef:      mr.GetSourceRef(),
		TargetRef:      mr.GetTargetRef(),
		Title:          mr.GetTitle(),
		Description:    mr.GetDescription(),
		CreatorID:      mr.GetCreatorId(),
		State:          mr.GetState().String(),
		HeadRevision:   mr.GetHeadRevision(),
		Version:        mr.GetVersion(),
		ExternalIssues: shapeExternalIssues(mr.GetExternalIssues()),
		CreatedAt:      created,
	}
}
