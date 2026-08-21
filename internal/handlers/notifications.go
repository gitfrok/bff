// notifications.go is the notifications read surface (SPEC-0063, ADR-0086):
// the bell's list, unread count, and mark-read. It shapes and forwards; the
// recipient is the session-verified caller, forwarded as the wire context, so
// no request can name somebody else's rows.
package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/notifications"
)

// NotificationsClient is the narrow port this surface shapes.
type NotificationsClient interface {
	List(ctx context.Context, read aggregate.ReadContext, pageSize int, pageToken string) (notifications.Page, error)
	UnreadCount(context.Context, aggregate.ReadContext) (int64, error)
	MarkRead(context.Context, aggregate.ReadContext, string) (*notifications.Notification, error)
}

// NotificationsHandler serves the bell surface.
type NotificationsHandler struct {
	client  NotificationsClient
	session Session
}

// NewNotifications wires the handler onto the notifications client.
func NewNotifications(client NotificationsClient, session Session) *NotificationsHandler {
	return &NotificationsHandler{client: client, session: session}
}

// NotificationView is one shaped row the browser renders: what happened,
// where, when — and whether it has been read (SPEC-0063 AC7).
type NotificationView struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	RepositoryID   string `json:"repository_id"`
	MergeRequestID string `json:"merge_request_id,omitempty"`
	ActorID        string `json:"actor_id,omitempty"`
	HeadRevision   string `json:"head_revision,omitempty"`
	OccurredAt     string `json:"occurred_at"`
	Read           bool   `json:"read"`
}

// NotificationsPageView is the JSON list shape. Notifications is never null
// so an empty page marshals identically every time.
type NotificationsPageView struct {
	Notifications []NotificationView `json:"notifications"`
	NextPageToken string             `json:"next_page_token"`
}

// UnreadCountView is the JSON count shape. Zero marshals as zero: the bell
// renders absence honestly.
type UnreadCountView struct {
	Unread int64 `json:"unread"`
}

func deniedNotifications(w http.ResponseWriter) {
	http.Error(w, `{"error":"unavailable"}`, http.StatusNotFound)
}

// Routes returns the notifications surface's handler set.
func (h *NotificationsHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/notifications", h.list)
	mux.HandleFunc("GET /v1/notifications/unread_count", h.unreadCount)
	mux.HandleFunc("POST /v1/notifications/{notification_id}/mark_read", h.markRead)
	return mux
}

func notificationView(n notifications.Notification) NotificationView {
	return NotificationView{
		ID:             n.ID,
		Kind:           string(n.Kind),
		RepositoryID:   n.RepositoryID,
		MergeRequestID: n.MergeRequestID,
		ActorID:        n.ActorID,
		HeadRevision:   n.HeadRevision,
		OccurredAt:     n.OccurredAt.UTC().Format(time.RFC3339),
		Read:           n.Read,
	}
}

// list serves GET /v1/notifications?page_size=&page_token=.
func (h *NotificationsHandler) list(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedNotifications(w)
		return
	}
	pageSize := 0
	if raw := r.URL.Query().Get("page_size"); raw != "" {
		size, err := strconv.Atoi(raw)
		if err != nil || size < 0 {
			deniedNotifications(w)
			return
		}
		pageSize = size
	}
	page, err := h.client.List(r.Context(), read, pageSize, r.URL.Query().Get("page_token"))
	if err != nil {
		deniedNotifications(w)
		return
	}
	view := NotificationsPageView{
		Notifications: make([]NotificationView, 0, len(page.Notifications)),
		NextPageToken: page.NextPageToken,
	}
	for _, n := range page.Notifications {
		view.Notifications = append(view.Notifications, notificationView(n))
	}
	writeJSON(w, view)
}

// unreadCount serves GET /v1/notifications/unread_count.
func (h *NotificationsHandler) unreadCount(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedNotifications(w)
		return
	}
	count, err := h.client.UnreadCount(r.Context(), read)
	if err != nil {
		deniedNotifications(w)
		return
	}
	writeJSON(w, UnreadCountView{Unread: count})
}

// markRead serves POST /v1/notifications/{notification_id}/mark_read.
func (h *NotificationsHandler) markRead(w http.ResponseWriter, r *http.Request) {
	read, ok := h.session.ReadContext(r)
	if !ok || read.TenantID == "" || read.ActorID == "" {
		deniedNotifications(w)
		return
	}
	shaped, err := h.client.MarkRead(r.Context(), read, r.PathValue("notification_id"))
	if err != nil || shaped == nil {
		deniedNotifications(w)
		return
	}
	writeJSON(w, notificationView(*shaped))
}
