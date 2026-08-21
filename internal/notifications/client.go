// Package notifications adapts the generated NotificationService gRPC client
// onto BFF-shaped types (SPEC-0063, ADR-0086). It shapes and forwards: the
// recipient is the session-verified caller forwarded as the wire context, and
// the backend owns every decision (invariant 18).
package notifications

import (
	"context"
	"time"

	notificationsv1 "github.com/gitfrok/bff/gen/proto/notifications/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

// Client talks to the backend's NotificationService.
type Client struct {
	service notificationsv1.NotificationServiceClient
}

// New wires the adapter onto the generated client.
func New(service notificationsv1.NotificationServiceClient) *Client {
	return &Client{service: service}
}

func contextOf(read aggregate.ReadContext) *notificationsv1.NotificationContext {
	return &notificationsv1.NotificationContext{
		TenantId: read.TenantID,
		ActorId:  read.ActorID,
	}
}

// Kind is what happened, mirroring the contract's vocabulary.
type Kind string

const (
	KindMergeRequestReadyForReview Kind = "MERGE_REQUEST_READY_FOR_REVIEW"
	KindReviewSubmitted            Kind = "REVIEW_SUBMITTED"
	KindMergeRequestMerged         Kind = "MERGE_REQUEST_MERGED"
	KindFindingsAttributed         Kind = "FINDINGS_ATTRIBUTED"
)

var kindOf = map[string]Kind{
	notificationsv1.NotificationKind_NOTIFICATION_KIND_MERGE_REQUEST_READY_FOR_REVIEW.String(): KindMergeRequestReadyForReview,
	notificationsv1.NotificationKind_NOTIFICATION_KIND_REVIEW_SUBMITTED.String():               KindReviewSubmitted,
	notificationsv1.NotificationKind_NOTIFICATION_KIND_MERGE_REQUEST_MERGED.String():           KindMergeRequestMerged,
	notificationsv1.NotificationKind_NOTIFICATION_KIND_FINDINGS_ATTRIBUTED.String():            KindFindingsAttributed,
}

// Notification is one shaped row the bell or list page renders.
type Notification struct {
	ID             string
	Kind           Kind
	RepositoryID   string
	MergeRequestID string
	ActorID        string
	HeadRevision   string
	OccurredAt     time.Time
	Read           bool
}

// Page is one page of notifications, newest first.
type Page struct {
	Notifications []Notification
	NextPageToken string
}

func shape(n *notificationsv1.Notification) Notification {
	shaped := Notification{
		ID:             n.GetNotificationId(),
		Kind:           kindOf[n.GetKind().String()],
		RepositoryID:   n.GetRepositoryId(),
		MergeRequestID: n.GetMergeRequestId(),
		ActorID:        n.GetActorId(),
		HeadRevision:   n.GetHeadRevision(),
		Read:           n.GetRead(),
	}
	if at := n.GetOccurredAt(); at != nil {
		shaped.OccurredAt = at.AsTime()
	}
	return shaped
}

// List returns one page of the caller's notifications, newest first.
func (c *Client) List(ctx context.Context, read aggregate.ReadContext, pageSize int, pageToken string) (Page, error) {
	response, err := c.service.ListNotifications(ctx, &notificationsv1.ListNotificationsRequest{
		Context:   contextOf(read),
		PageSize:  int32(pageSize),
		PageToken: pageToken,
	})
	if err != nil {
		return Page{}, err
	}
	page := Page{NextPageToken: response.GetNextPageToken()}
	for _, n := range response.GetNotifications() {
		page.Notifications = append(page.Notifications, shape(n))
	}
	if page.Notifications == nil {
		page.Notifications = []Notification{}
	}
	return page, nil
}

// UnreadCount returns exactly that; zero is zero (SPEC-0063 AC7).
func (c *Client) UnreadCount(ctx context.Context, read aggregate.ReadContext) (int64, error) {
	response, err := c.service.UnreadCount(ctx, &notificationsv1.UnreadCountRequest{Context: contextOf(read)})
	if err != nil {
		return 0, err
	}
	return response.GetUnread(), nil
}

// MarkRead marks ONE notification read for the caller (SPEC-0063 AC6).
func (c *Client) MarkRead(ctx context.Context, read aggregate.ReadContext, notificationID string) (*Notification, error) {
	response, err := c.service.MarkRead(ctx, &notificationsv1.MarkReadRequest{
		Context:        contextOf(read),
		NotificationId: notificationID,
	})
	if err != nil {
		return nil, err
	}
	shaped := shape(response.GetNotification())
	return &shaped, nil
}
