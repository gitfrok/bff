// Command bff is the Backend-for-Frontend entrypoint. It aggregates/shapes only (invariant 18)
// and talks to backend over gRPC using generated contracts — never importing backend internals.
package main

import (
	"fmt"

	agentv1 "github.com/gitfrok/bff/gen/proto/agent/v1"
)

func main() {
	// Generated contract wired in to prove codegen composes in this module (T-0001 AC3/AC4).
	_ = agentv1.HealthState_HEALTHY
	fmt.Println("gitfrok bff: baseline (T-0001)")
}
