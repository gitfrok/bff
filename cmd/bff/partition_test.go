package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// SPEC-0070 AC5/AC6: each plane serves its own route set and none of the other's.
//
// Asserted over the source, because the registrations live in a composition root that dials
// Postgres, Valkey and two gRPC doors to reach them. What this proves is exactly what ADR-0094
// decisions 3 and 4 partition — which paths a deployment answers — and it proves it as SETS, so a
// route added to the wrong branch fails here rather than reaching a plane it should not.

var routePattern = regexp.MustCompile(`mux\.Handle(?:Func)?\("([^"]+)"`)

// planeRoutes splits main.go's registration block at the `if cfg.IsControl()` boundary.
func planeRoutes(t *testing.T) (control, data []string) {
	t.Helper()

	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(body)

	// Anchor on the partition's own marker, not on `if cfg.IsControl()`: that condition appears
	// three times in main.go — selecting metaConn, partitioning the routes, and printing the
	// startup line — and the first match is the metaConn one, which registers nothing. The first
	// version of this test anchored on the condition and reported "no control-plane routes found",
	// which is a true statement about the wrong block.
	const marker = "// THE ROUTE PARTITION"
	head := strings.Index(src, marker)
	if head < 0 {
		t.Fatal("main.go has no route-partition block — SPEC-0070 AC5/AC6 requires one")
	}
	split := strings.Index(src[head:], "\n\t} else {")
	if split < 0 {
		t.Fatal("the control-plane branch has no data-plane counterpart")
	}
	tail := strings.Index(src[head+split:], "\n\t}\n")
	if tail < 0 {
		t.Fatal("the data-plane branch is unterminated")
	}

	for _, m := range routePattern.FindAllStringSubmatch(src[head:head+split], -1) {
		control = append(control, m[1])
	}
	for _, m := range routePattern.FindAllStringSubmatch(src[head+split:head+split+tail], -1) {
		data = append(data, m[1])
	}
	sort.Strings(control)
	sort.Strings(data)
	return control, data
}

// AC5: a control-plane deployment serves no repository route. The check is on the PATH, so a route
// added to the wrong branch is caught by shape rather than by an enumerated list going stale.
func TestControlPlaneServesNoRepositoryRoute(t *testing.T) {
	t.Parallel()

	control, _ := planeRoutes(t)
	if len(control) == 0 {
		t.Fatal("no control-plane routes found")
	}

	for _, r := range control {
		for _, forbidden := range []string{"/v1/repositories", "/api/v1/search", "/api/v1/security", "/api/v1/pipelines", "/v1/notifications"} {
			if strings.Contains(r, forbidden) {
				t.Errorf("control-plane route %q serves %s — ADR-0094 decision 4 gives the control plane "+
					"no repository content, and ADR-0100 decisions 2 and 3 put the list, settings and "+
					"notifications data-side", r, forbidden)
			}
		}
	}
}

// AC6: a data-plane deployment serves none of decision 4's metadata surfaces.
func TestDataPlaneServesNoMetadataRoute(t *testing.T) {
	t.Parallel()

	_, data := planeRoutes(t)
	if len(data) == 0 {
		t.Fatal("no data-plane routes found")
	}

	for _, r := range data {
		for _, forbidden := range []string{"/api/v1/audit/", "/api/v1/usage/", "/api/v1/policy/", "/v1/admin/"} {
			if strings.Contains(r, forbidden) {
				t.Errorf("data-plane route %q serves %s — ADR-0094 decision 4 keeps that on the control plane", r, forbidden)
			}
		}
	}
}

// The two sets must be disjoint. A path registered in both branches would be a route whose plane
// depends on which branch the compiler reached first, which is not a partition.
func TestPlaneRouteSetsAreDisjoint(t *testing.T) {
	t.Parallel()

	control, data := planeRoutes(t)
	inControl := map[string]bool{}
	for _, r := range control {
		inControl[r] = true
	}
	for _, r := range data {
		if inControl[r] {
			t.Errorf("route %q is registered on BOTH planes; the partition is not one", r)
		}
	}
}

// The login catch-all belongs to the control plane (ADR-0094 decision 4, and ADR-0100 decision 1
// moves OIDCLogin there). Asserted because its absence from the data plane is what makes an
// unmatched repository path a coarse 404 rather than a redirect into a login flow.
func TestLoginIsControlPlaneOnly(t *testing.T) {
	t.Parallel()

	control, data := planeRoutes(t)
	if !contains(control, "/") {
		t.Error(`the "/" login catch-all is not on the control plane; ADR-0094 decision 4 puts identity and login there`)
	}
	if contains(data, "/") {
		t.Error(`the "/" catch-all is on the data plane, so an unmatched repository path would reach a login flow ` +
			`instead of a coarse 404 (SPEC-0070 AC5)`)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
