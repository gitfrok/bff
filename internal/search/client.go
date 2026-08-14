// Package search adapts the generated SearchService gRPC client onto
// BFF-shaped request/response types. It carries verified identity and shapes
// only (SPEC-0034, SPEC-0035, T-0028): the backend is the PDP for
// search.read and search.index.status.read, the searchable repository set is
// derived server-side at query time, and nothing here filters, ranks, or
// authorizes (invariant 18).
package search

import (
	"context"
	"errors"
	"slices"
	"time"

	searchv1 "github.com/gitfrok/bff/gen/proto/search/v1"
	"github.com/gitfrok/bff/internal/aggregate"
)

// ErrMalformed refuses a request whose shape the contract does not name. It
// is coarse: the caller learns nothing about what exists or what is allowed.
var ErrMalformed = errors.New("search: malformed request")

// Mode names the query languages the contract defines. Nothing else is a
// query; an unnamed mode is ErrMalformed, not a default.
type Mode string

const (
	ModeSubstring Mode = "SUBSTRING"
	ModeRegex     Mode = "REGEX"
	ModeSymbol    Mode = "SYMBOL"
)

// ModeOf maps the wire name onto the contract enum. The second result is
// false for anything the contract does not name.
func ModeOf(name string) (Mode, bool) {
	switch Mode(name) {
	case ModeSubstring, ModeRegex, ModeSymbol:
		return Mode(name), true
	default:
		return "", false
	}
}

// Query is one code query. It carries no repository allow-list, permission
// claim, authorization flag, or scoring override: the contract has no fields
// for them, so a request cannot assert scope (SPEC-0035 AC2).
type Query struct {
	Text             string
	Mode             Mode
	ResultLimit      int32
	ContextLineLimit int32
	PageToken        string
}

// Result is one authorized match, shaped for the browser. It carries opaque
// identifiers and bounded content only — no permission fact.
type Result struct {
	RepositoryID   string
	Revision       string
	Path           string
	LineStart      int64
	LineEnd        int64
	MatchedContent string
}

// Page is one result page. It has no total and no field capable of
// expressing unauthorized matches, so non-enumeration is a type property
// (SPEC-0035 AC3).
type Page struct {
	Results       []Result
	NextPageToken string
}

// IndexStatus is one repository's freshness record. Which repositories
// appear is the backend's decision; the BFF shapes what it is given and
// cannot ask about a repository the caller may not read (SPEC-0035 AC6).
type IndexStatus struct {
	RepositoryID        string
	LastIndexedRevision string
	IndexedAt           time.Time
	FreshnessLag        time.Duration
}

// Client talks to the backend's SearchService.
type Client struct {
	service searchv1.SearchServiceClient
}

// New wires the adapter onto the generated client.
func New(service searchv1.SearchServiceClient) *Client {
	return &Client{service: service}
}

// contextOf maps the verified session identity onto the wire context. The
// context names no repository: the searchable set is server-derived, never
// caller-supplied (SPEC-0035 AC2).
func contextOf(read aggregate.ReadContext) *searchv1.SearchContext {
	return &searchv1.SearchContext{
		TenantId:   read.TenantID,
		ActorId:    read.ActorID,
		ActorRoles: slices.Clone(read.ActorRoles),
		RequestId:  read.RequestID,
	}
}

func wireMode(mode Mode) (searchv1.QueryMode, bool) {
	switch mode {
	case ModeSubstring:
		return searchv1.QueryMode_QUERY_MODE_SUBSTRING, true
	case ModeRegex:
		return searchv1.QueryMode_QUERY_MODE_REGEX, true
	case ModeSymbol:
		return searchv1.QueryMode_QUERY_MODE_SYMBOL, true
	default:
		return searchv1.QueryMode_QUERY_MODE_UNSPECIFIED, false
	}
}

// Search runs one tenant-scoped query and shapes the authorized page.
func (c *Client) Search(ctx context.Context, read aggregate.ReadContext, q Query) (Page, error) {
	mode, ok := wireMode(q.Mode)
	if !ok {
		return Page{}, ErrMalformed
	}
	response, err := c.service.Search(ctx, &searchv1.SearchRequest{
		Context:          contextOf(read),
		Query:            q.Text,
		Mode:             mode,
		ResultLimit:      q.ResultLimit,
		ContextLineLimit: q.ContextLineLimit,
		PageToken:        q.PageToken,
	})
	if err != nil {
		return Page{}, err
	}
	page := Page{Results: make([]Result, 0, len(response.GetResults())), NextPageToken: response.GetNextPageToken()}
	for _, m := range response.GetResults() {
		page.Results = append(page.Results, Result{
			RepositoryID:   m.GetRepositoryId(),
			Revision:       m.GetRevision(),
			Path:           m.GetPath(),
			LineStart:      m.GetLineStart(),
			LineEnd:        m.GetLineEnd(),
			MatchedContent: m.GetMatchedContent(),
		})
	}
	return page, nil
}

// IndexStatus reports freshness for the repositories the backend admits the
// caller may read; a repository the caller may not read appears in no entry.
func (c *Client) IndexStatus(ctx context.Context, read aggregate.ReadContext) ([]IndexStatus, error) {
	response, err := c.service.GetIndexStatus(ctx, &searchv1.GetIndexStatusRequest{Context: contextOf(read)})
	if err != nil {
		return nil, err
	}
	entries := make([]IndexStatus, 0, len(response.GetEntries()))
	for _, e := range response.GetEntries() {
		entry := IndexStatus{
			RepositoryID:        e.GetRepositoryId(),
			LastIndexedRevision: e.GetLastIndexedRevision(),
		}
		if t := e.GetIndexedAt(); t != nil {
			entry.IndexedAt = t.AsTime()
		}
		if d := e.GetFreshnessLag(); d != nil {
			entry.FreshnessLag = d.AsDuration()
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
