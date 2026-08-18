// Package pipelines adapts the CI job list onto BFF-shaped types (T-0060, SPEC-0054).
//
// It carries verified identity and shapes only. The listable set is derived by the backend from the
// caller's authorization at request time, and the request has no field a caller could use to widen
// it.
//
// Nothing here carries job output. ADR-0072 defers retaining it to its own decision, and
// check-contracts.sh check 13 keeps the wire free of a field for it — this package would have
// nowhere to put one even if someone tried.
package pipelines

import (
	"context"
	"errors"
	"time"

	civ1 "github.com/gitfrok/bff/gen/proto/ci/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ErrUnavailable is the one coarse refusal this surface returns.
var ErrUnavailable = errors.New("pipelines: unavailable")

// Run is one pipeline run as the caller observes it.
type Run struct {
	JobID          string
	RepositoryID   string
	Ref            string
	CommitSHA      string
	Trigger        string
	State          string
	QueuedAt       string
	StartedAt      string
	FinishedAt     string
	OutcomeSummary string
	DelayCause     string
}

// Page is one page of runs. No total: no field may express how many runs the caller may not see.
type Page struct {
	Runs          []Run
	NextPageToken string
}

// Client is the runs port this surface shapes.
type Client struct {
	jobs civ1.CIJobServiceClient
}

// New wires the client onto the generated stub.
func New(jobs civ1.CIJobServiceClient) *Client { return &Client{jobs: jobs} }

// List asks which runs the caller may see.
func (c *Client) List(ctx context.Context, read aggregate.ReadContext, repositoryID, pageToken string, pageSize int32) (Page, error) {
	if read.TenantID == "" || read.ActorID == "" {
		return Page{}, ErrUnavailable
	}
	response, err := c.jobs.ListJobs(ctx, &civ1.ListJobsRequest{
		Context: &civ1.JobContext{
			TenantId:   read.TenantID,
			ActorId:    read.ActorID,
			RequestId:  read.RequestID,
			ActorRoles: read.ActorRoles,
		},
		RepositoryId: repositoryID,
		PageToken:    pageToken,
		PageSize:     pageSize,
	})
	if err != nil {
		return Page{}, ErrUnavailable
	}
	page := Page{Runs: make([]Run, 0, len(response.GetJobs())), NextPageToken: response.GetNextPageToken()}
	for _, job := range response.GetJobs() {
		page.Runs = append(page.Runs, Run{
			JobID:          job.GetJobId(),
			RepositoryID:   job.GetRepositoryId(),
			Ref:            job.GetRef(),
			CommitSHA:      job.GetCommitSha(),
			Trigger:        job.GetTriggerKind().String(),
			State:          job.GetState().String(),
			QueuedAt:       stamp(job.GetQueuedAt()),
			StartedAt:      stamp(job.GetStartedAt()),
			FinishedAt:     stamp(job.GetFinishedAt()),
			OutcomeSummary: job.GetOutcomeSummary(),
		})
	}
	return page, nil
}

// stamp renders a protobuf timestamp as RFC3339, or empty when it is absent.
//
// An absent started_at means the job has not started, and it renders as empty
// rather than as the zero instant — 1970 in a timings column is a fact nobody
// asserted.
func stamp(ts *timestamppb.Timestamp) string {
	if ts == nil || !ts.IsValid() {
		return ""
	}
	return ts.AsTime().UTC().Format(time.RFC3339)
}
