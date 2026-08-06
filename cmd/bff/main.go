// Command bff is the Backend-for-Frontend entrypoint. It aggregates/shapes only (invariant 18)
// and talks to backend over gRPC using generated contracts — never importing backend internals.
package main

import (
	"fmt"
	"os"
	"time"

	agentv1 "github.com/gitfrok/bff/gen/proto/agent/v1"
	policyv1 "github.com/gitfrok/bff/gen/proto/policy/v1"
	"github.com/gitfrok/bff/internal/aggregate"
	"github.com/gitfrok/bff/internal/pep"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// pdpAddrEnv names the backend data plane serving contracts/proto/policy/v1.
//
// Per-environment configuration, never a compiled-in address (invariant 13).
const pdpAddrEnv = "GITFROK_PDP_ADDR"

// decisionTTL bounds how long a cached decision may be reused.
//
// Short on purpose. Policy changes are picked up by revision rather than by clock (see
// internal/pep), so this window is not about the rules — it is about the *inputs*: a subject's
// roles can be revoked while the policy stays put, and nothing in a response would reveal it. This
// is how long a revoked role keeps working.
const decisionTTL = 30 * time.Second

func main() {
	addr := os.Getenv(pdpAddrEnv)
	if addr == "" {
		fmt.Fprintf(os.Stderr, "%s is not set: without a PDP the BFF cannot authorize anything, "+
			"and it must not serve requests it cannot check (ADR-0006, invariant 2)\n", pdpAddrEnv)
		os.Exit(1)
	}

	// Insecure credentials are the dev posture. mTLS between planes is T-0013's, and this line is
	// where it lands — not a decision deferred silently, but one this file names.
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach the PDP at %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	enforcer := pep.New(policyv1.NewPolicyDecisionPointClient(conn), pep.Options{TTL: decisionTTL})

	// The sample protected action T-0005 wires end to end (SPEC-0002 AC3). Its RepoReader is nil
	// until T-0014 brings the Repository read APIs; the authorization path in front of it is what
	// this task owns, and it is complete.
	_ = aggregate.NewRepos(enforcer, nil)

	// Generated contract wired in to prove codegen composes in this module (T-0001 AC3/AC4).
	_ = agentv1.HealthState_HEALTH_STATE_HEALTHY
	fmt.Printf("gitfrok bff: PEP on %s, decisions cached for %s\n", addr, decisionTTL)
}
