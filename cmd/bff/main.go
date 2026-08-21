// Command bff is the Backend-for-Frontend entrypoint. It aggregates/shapes only (invariant 18)
// and talks to backend over gRPC using generated contracts — never importing backend internals.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	agentv1 "github.com/gitfrok/bff/gen/proto/agent/v1"
	auditv1 "github.com/gitfrok/bff/gen/proto/audit/v1"
	civ1 "github.com/gitfrok/bff/gen/proto/ci/v1"
	codereviewv1 "github.com/gitfrok/bff/gen/proto/codereview/v1"
	identityv1 "github.com/gitfrok/bff/gen/proto/identity/v1"
	notificationsv1 "github.com/gitfrok/bff/gen/proto/notifications/v1"
	policyv1 "github.com/gitfrok/bff/gen/proto/policy/v1"
	releasev1 "github.com/gitfrok/bff/gen/proto/release/v1"
	repositoryv1 "github.com/gitfrok/bff/gen/proto/repository/v1"
	searchv1 "github.com/gitfrok/bff/gen/proto/search/v1"
	securityv1 "github.com/gitfrok/bff/gen/proto/security/v1"
	usagev1 "github.com/gitfrok/bff/gen/proto/usage/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/audit"
	"github.com/gitfrok/bff/internal/browser"
	"github.com/gitfrok/bff/internal/codereview"
	"github.com/gitfrok/bff/internal/fleet"
	"github.com/gitfrok/bff/internal/handlers"
	"github.com/gitfrok/bff/internal/identity"
	"github.com/gitfrok/bff/internal/login"
	"github.com/gitfrok/bff/internal/mr"
	"github.com/gitfrok/bff/internal/notifications"
	"github.com/gitfrok/bff/internal/oidc"
	"github.com/gitfrok/bff/internal/pep"
	"github.com/gitfrok/bff/internal/pipelines"
	"github.com/gitfrok/bff/internal/policyview"
	"github.com/gitfrok/bff/internal/releases"
	"github.com/gitfrok/bff/internal/reposettings"
	"github.com/gitfrok/bff/internal/repositoryreader"
	"github.com/gitfrok/bff/internal/repositoryregistry"
	"github.com/gitfrok/bff/internal/search"
	"github.com/gitfrok/bff/internal/security"
	"github.com/gitfrok/bff/internal/session"
	"github.com/gitfrok/bff/internal/usage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// pdpAddrEnv names the backend data plane serving contracts/proto/policy/v1.
// The same door serves codereview and the OIDC login surface.
//
// Per-environment configuration, never a compiled-in address (invariant 13).
const (
	pdpAddrEnv         = "GITFROK_PDP_ADDR"
	readerAddrEnv      = "GITFROK_REPOSITORY_READER_ADDR"
	listenAddrEnv      = "GITFROK_BFF_LISTEN_ADDR"
	oidcIssuerEnv      = "GITFROK_OIDC_ISSUER"
	oidcClientIDEnv    = "GITFROK_OIDC_CLIENT_ID"
	oidcRedirectURIEnv = "GITFROK_OIDC_REDIRECT_URI"
	oidcScopeEnv       = "GITFROK_OIDC_SCOPE"
	sessionStoreEnv    = "GITFROK_SESSION_STORE"
	sessionAddrEnv     = "GITFROK_SESSION_VALKEY_ADDR"
	sessionPasswordEnv = "GITFROK_SESSION_VALKEY_PASSWORD"
	// usageAddrEnv names the control plane door serving contracts/proto/usage/v1.
	// Unset means the usage view surface is not mounted: the control plane's
	// usage door is itself optional (GITFROK_USAGE_GRPC_ADDR over there).
	usageAddrEnv = "GITFROK_USAGE_ADDR"
	// fleetAddrEnv names the control plane door serving agent/v1's FleetReader —
	// the admin area's fleet report (SPEC-0058). Unset means the report reads
	// unavailable, which is a different statement from an empty fleet.
	fleetAddrEnv = "GITFROK_FLEET_ADDR"
)

// decisionTTL bounds how long a cached decision may be reused.
//
// Short on purpose. Policy changes are picked up by revision rather than by clock (see
// internal/pep), so this window is not about the rules — it is about the *inputs*: a subject's
// roles can be revoked while the policy stays put, and nothing in a response would reveal it. This
// is how long a revoked role keeps working.
const decisionTTL = 30 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pdpAddr := os.Getenv(pdpAddrEnv)
	if pdpAddr == "" {
		fmt.Fprintf(os.Stderr, "%s is not set: without a PDP the BFF cannot authorize anything, "+
			"and it must not serve requests it cannot check (ADR-0006, invariant 2)\n", pdpAddrEnv)
		os.Exit(1)
	}
	readerAddr := os.Getenv(readerAddrEnv)
	if readerAddr == "" {
		fmt.Fprintf(os.Stderr, "%s is not set: without RepositoryReader the browser has no data to show\n", readerAddrEnv)
		os.Exit(1)
	}
	listenAddr := os.Getenv(listenAddrEnv)
	if listenAddr == "" {
		fmt.Fprintf(os.Stderr, "%s is not set: the BFF must serve somewhere\n", listenAddrEnv)
		os.Exit(1)
	}

	// Insecure credentials are the dev posture. mTLS between planes is T-0013's, and this line is
	// where it lands — not a decision deferred silently, but one this file names.
	pdpConn, err := grpc.NewClient(pdpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach the PDP at %s: %v\n", pdpAddr, err)
		os.Exit(1)
	}
	defer func() { _ = pdpConn.Close() }()

	readerConn, err := grpc.NewClient(readerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach RepositoryReader at %s: %v\n", readerAddr, err)
		os.Exit(1)
	}
	defer func() { _ = readerConn.Close() }()

	enforcer := pep.New(policyv1.NewPolicyDecisionPointClient(pdpConn), pep.Options{TTL: decisionTTL})
	_ = enforcer

	// The session store. ADR-0049 decision 5 names Valkey and ADR-0052 permits this process to open
	// it — the one datastore the BFF may hold, because a session is its own state.
	//
	// A configured store that cannot be reached is fatal (ADR-0052 decision 4). Falling back to
	// memory here would leave the process looking healthy while logging every user out on the next
	// rollout, and nothing in a response would say why.
	var store session.Store
	switch mode := os.Getenv(sessionStoreEnv); mode {
	case "valkey":
		dial, cancel := context.WithTimeout(ctx, 10*time.Second)
		valkey, err := session.Dial(dial, os.Getenv(sessionAddrEnv), os.Getenv(sessionPasswordEnv))
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s=valkey but the store is unusable: %v\n"+
				"set %s, or set %s=memory to accept sessions that die with this process\n",
				sessionStoreEnv, err, sessionAddrEnv, sessionStoreEnv)
			os.Exit(1)
		}
		defer func() { _ = valkey.Close() }()
		store = valkey
	case "", "memory":
		// The dev posture: a restart logs everyone out, which is the correct failure mode for state
		// whose loss is an inconvenience rather than a correctness break.
		store = session.NewMemory()
	default:
		fmt.Fprintf(os.Stderr, "%s=%q is not a store: use valkey or memory\n", sessionStoreEnv, mode)
		os.Exit(1)
	}
	sessions := session.NewManager(store)

	// The browser surface: RepositoryReader (served by git-storaged) shapes tree/file/diff.
	reader := aggregate.NewRepositoryReader(repositoryreader.New(repositoryv1.NewRepositoryReaderClient(readerConn)))

	// Code Review (served by the data plane) shapes the MR surface.
	review := codereview.New(codereviewv1.NewMergeRequestServiceClient(pdpConn))
	// Notifications (T-0080, SPEC-0063): the bell's read surface. Same door,
	// same session-verified context; the recipient IS the caller.
	notificationsHandler := handlers.NewNotifications(
		notifications.New(notificationsv1.NewNotificationServiceClient(pdpConn)), sessions)

	// Code Search (served by the data plane) shapes the search surface. The
	// backend is the PDP for search.read and search.index.status.read; this
	// handler forwards the session's verified identity and shapes only, its
	// one addition being the RepositoryReader metadata joined onto each
	// authorized match (SPEC-0034, SPEC-0035, T-0028).
	searchHandler := handlers.NewSearch(search.New(searchv1.NewSearchServiceClient(pdpConn)), reader, sessions)

	// Security/Findings (served by the data plane) shapes the unified
	// security dashboard surface. The backend is the PDP for findings.read,
	// findings.summary.read and findings.triage; this handler forwards the
	// session's verified identity and shapes only — counts, facets and triage
	// transitions are all computed under server-derived authorization
	// (SPEC-0026, SPEC-0027, T-0023). The MR findings route serves the same
	// surface: attribution is the backend's derived state, never computed
	// here (SPEC-0028, T-0024).
	securityHandler := handlers.NewSecurity(security.New(securityv1.NewFindingsServiceClient(pdpConn)), sessions)

	// Audit (served by the data plane) shapes the date-ranged evidence pack
	// surface. The backend is the PDP for evidence.pack.generate and
	// evidence.pack.read: assembly is entirely server-determined and itself
	// audited; this handler forwards the session's verified identity and
	// shapes only, streaming each bounded pack chunk as it arrives
	// (SPEC-0031, SPEC-0032, T-0026).
	evidenceHandler := handlers.NewEvidence(audit.New(auditv1.NewEvidenceServiceClient(pdpConn)), sessions)

	// Identity & Access (served by the data plane) shapes the auditor grant
	// administration surface. The backend is the PDP for auditor.grant.manage:
	// issuing, revoking and listing are owner-only decisions, each lifecycle
	// action is itself audited, and grant state is a fact the backend reads at
	// decision time; this handler forwards the session's verified identity and
	// shapes only (SPEC-0033, T-0027).
	grantsHandler := handlers.NewAuditorGrants(identity.New(identityv1.NewAuditorGrantServiceClient(pdpConn)), sessions)

	// Usage (served by the control plane) shapes the fair-use usage view.
	// The backend is the metering authority and the PDP for usage.view.read
	// (ADR-0061): the numbers are the same counters every envelope decision
	// is made from, and this handler forwards the session's verified
	// identity and shapes only — no number is computed, adjusted, or
	// invented here, and unmeasured dimensions carry no number at all
	// (SPEC-0041, T-0034). The door is optional: an unset address leaves
	// the surface unmounted rather than serving a view with no authority
	// behind it.
	var usageHandler *handlers.UsageHandler
	if usageAddr := os.Getenv(usageAddrEnv); usageAddr != "" {
		usageConn, err := grpc.NewClient(usageAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot reach the usage service at %s: %v\n", usageAddr, err)
			os.Exit(1)
		}
		defer func() { _ = usageConn.Close() }()
		usageHandler = handlers.NewUsage(usage.New(usagev1.NewUsageServiceClient(usageConn)), sessions)
	} else {
		fmt.Fprintf(os.Stderr, "%s is not set: the usage view surface is not mounted\n", usageAddrEnv)
	}

	// The admin area's fleet report (T-0072, SPEC-0058). Its own control-plane
	// address, so a deployment may serve one without the other — and so a BFF that
	// was not given the address answers "unavailable" rather than reporting an empty
	// fleet, which would tell an administrator their tenant has no data planes.
	//
	// A nil client is the unconfigured door and refuses every call, which is why the
	// handler is mounted either way: the surface says the report is unavailable
	// rather than 404-ing the whole admin destination.
	var fleetClient *fleet.Client
	if fleetAddr := os.Getenv(fleetAddrEnv); fleetAddr != "" {
		fleetConn, err := grpc.NewClient(fleetAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot reach the fleet reader at %s: %v\n", fleetAddr, err)
			os.Exit(1)
		}
		defer func() { _ = fleetConn.Close() }()
		fleetClient = fleet.New(agentv1.NewFleetReaderClient(fleetConn))
	} else {
		fmt.Fprintf(os.Stderr, "%s is not set: the admin area's fleet report reads unavailable\n", fleetAddrEnv)
		fleetClient = fleet.New(nil)
	}

	// Imported review history (SPEC-0011) is read through the same door. It is a
	// separate service in the contracts, and stays a separate client here: the
	// two must never be shaped into one list the page cannot take apart.
	imports := codereview.NewImportClient(codereviewv1.NewImportServiceClient(pdpConn))

	// OIDC login (served by the data plane's Identity&Access).
	auth := oidc.New(identityv1.NewOIDCLoginClient(pdpConn))
	loginConfig := login.Config{
		Issuer:      os.Getenv(oidcIssuerEnv),
		ClientID:    os.Getenv(oidcClientIDEnv),
		RedirectURI: os.Getenv(oidcRedirectURIEnv),
		Scope:       os.Getenv(oidcScopeEnv),
	}
	if loginConfig.Scope == "" {
		loginConfig.Scope = "openid profile email"
	}
	loginHandler := login.New(loginConfig, auth, login.HTTPDiscovery{Client: &http.Client{Timeout: 10 * time.Second}}, sessions)

	// The HTTP surface. The browser handler is the SPEC-0021 surface; the MR
	// handler is the minimal T-0016 web bar; login owns /login, /callback and
	// /logout. Go's ServeMux prefers the most specific pattern, so the MR
	// routes (which name merge_requests) win over the browser prefix. The MR
	// handler's routes are registered directly so they coexist with the
	// browser prefix instead of conflicting with it.
	mux := http.NewServeMux()
	mux.Handle("/v1/repositories/", browser.New(reader, sessions).Routes())
	// The repository LIST, on /v1/repositories with no trailing slash. It is a
	// distinct pattern from the browser prefix above, which matches
	// /v1/repositories/... — a list names no repository, so it sits one level
	// up (T-0054, SPEC-0052).
	mux.Handle("GET /v1/repositories", handlers.NewRepositories(
		repositoryregistry.New(repositoryv1.NewRepositoryRegistryClient(pdpConn)), sessions))
	// Releases: tags, and the records announced against them (T-0065, SPEC-0056).
	// There is deliberately no artifact route beside these — ADR-0075 accepted
	// tags and notes only.
	releaseHandler := handlers.NewReleases(
		releases.New(releasev1.NewReleaseServiceClient(pdpConn), repositoryv1.NewRepositoryReaderClient(readerConn)),
		sessions)
	mux.Handle("GET /v1/repositories/{repository_id}/tags", releaseHandler)
	mux.Handle("GET /v1/repositories/{repository_id}/releases", releaseHandler)
	mux.Handle("POST /v1/repositories/{repository_id}/releases", releaseHandler)
	mux.Handle("GET /v1/repositories/{repository_id}/releases/{tag}", releaseHandler)
	mux.Handle("POST /v1/repositories/{repository_id}/releases/{tag}/notes", releaseHandler)
	// Repository settings: name, description and the archived label (T-0069, SPEC-0057). There is
	// deliberately no visibility route, no members route and no delete route — ADR-0076 accepted
	// name, description and archival only, and a door that exists and refuses is a promise nobody
	// has made.
	settingsHandler := handlers.NewRepoSettings(
		reposettings.New(repositoryv1.NewRepositorySettingsClient(pdpConn)), sessions)
	mux.Handle("GET /v1/repositories/{repository_id}/settings", settingsHandler)
	mux.Handle("POST /v1/repositories/{repository_id}/settings", settingsHandler)
	mux.Handle("POST /v1/repositories/{repository_id}/settings/archive", settingsHandler)
	// The admin area's fleet report (T-0072, SPEC-0058). One read, no audit route
	// beside it: the trail is reached through a grant, not through a role.
	mux.Handle("GET /v1/admin/fleet", handlers.NewFleet(fleetClient, sessions))

	mrHandler := mr.New(review, imports, sessions)
	mux.Handle("GET /v1/repositories/{repository_id}/merge_requests/{merge_request_id}", mrHandler)
	mux.Handle("POST /v1/repositories/{repository_id}/merge_requests", mrHandler)
	mux.Handle("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/review", mrHandler)
	// Referencing an issue in the customer's own tracker (T-0075, SPEC-0059). Two
	// writes and no read of its own: the reference travels on the merge request,
	// because there is no issue surface for it to belong to.
	mux.Handle("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/external_issues", mrHandler)
	mux.Handle("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/external_issues/unlink", mrHandler)
	mux.Handle("POST /v1/repositories/{repository_id}/merge_requests/{merge_request_id}/merge", mrHandler)
	mux.Handle("GET /v1/repositories/{repository_id}/imports/{import_id}/history", mrHandler)
	// The pipeline runs list (T-0060, SPEC-0054). There is deliberately no log
	// route beside it: ADR-0072 defers retaining job output, and a door that
	// exists and refuses is a promise nobody has made yet.
	// Policy visibility (T-0062, SPEC-0055). Reads only, and there is no write
	// route beside them: ADR-0073 records that authoring is structurally absent,
	// and a route that accepts a policy and refuses it would be a promise.
	policyReads := handlers.NewPolicy(policyview.New(policyv1.NewPolicyDecisionPointClient(pdpConn)), sessions)
	mux.Handle("GET /api/v1/policy/bundle", policyReads)
	mux.Handle("GET /api/v1/policy/decisions/{decision_id}", policyReads)
	mux.Handle("/v1/notifications", notificationsHandler.Routes())
	mux.Handle("POST /v1/notifications/{notification_id}/mark_read", notificationsHandler.Routes())
	mux.Handle("GET /api/v1/pipelines/runs", handlers.NewPipelines(
		pipelines.New(civ1.NewCIJobServiceClient(pdpConn)), sessions))
	mux.Handle("POST /api/v1/search/query", searchHandler)
	mux.Handle("GET /api/v1/search/status", searchHandler)
	mux.Handle("POST /api/v1/security/triage", securityHandler)
	mux.Handle("GET /api/v1/security/findings/summary", securityHandler)
	mux.Handle("GET /api/v1/security/dashboard", securityHandler)
	mux.Handle("GET /api/v1/security/merge-requests/{merge_request_id}/findings", securityHandler)
	mux.Handle("POST /api/v1/audit/evidence-packs", evidenceHandler)
	mux.Handle("GET /api/v1/audit/evidence-packs/{pack_id}/status", evidenceHandler)
	mux.Handle("GET /api/v1/audit/evidence-packs/{pack_id}", evidenceHandler)
	mux.Handle("POST /api/v1/audit/auditor-grants", grantsHandler)
	mux.Handle("DELETE /api/v1/audit/auditor-grants/{grant_id}", grantsHandler)
	mux.Handle("GET /api/v1/audit/auditor-grants", grantsHandler)
	if usageHandler != nil {
		mux.Handle("GET /api/v1/usage/view", usageHandler)
	}
	mux.Handle("/", loginHandler.Routes())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	context.AfterFunc(ctx, func() {
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	})

	fmt.Printf("gitfrok bff: PDP on %s, RepositoryReader on %s, serving %s\n", pdpAddr, readerAddr, listenAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "bff: %v\n", err)
		os.Exit(1)
	}
}
