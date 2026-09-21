// Package arch's plane-dial rule: a control-plane BFF deployment must hold no data-plane
// connection.
//
// SPEC-0070 AC8, and it lives HERE rather than in backend's internal/arch for a reason ADR-0094
// decision 7 named without naming the fix: that gate "walks only the backend's control-plane trees",
// and it cannot walk this repository because invariant 22 forbids backend depending on bff. A
// repository asserts about itself.
//
// What the rule checks is the composition root's control-plane branch. ADR-0100 decision 6 made the
// property structural — a control-plane deployment is given no data-plane address, so `dataConn` is
// nil — and this keeps it structural by refusing a control-plane route that reaches for one anyway.
// Without it the invariant holds by the author's care rather than by assertion, which is the exact
// wording ADR-0094 decision 7 used about the state it wanted fixed.
package arch

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// PlaneDialViolation is one control-plane registration that reaches a data-plane connection.
type PlaneDialViolation struct {
	Symbol string
	Line   int
	Detail string
}

func (v PlaneDialViolation) String() string {
	return fmt.Sprintf("%s (main.go:%d): %s", v.Symbol, v.Line, v.Detail)
}

// partitionMarker is the comment that opens the route partition. Anchoring on it rather than on
// `if cfg.IsControl()` is deliberate: that condition appears several times in main.go — selecting
// the meta connection, partitioning the routes, printing the startup line — and the first match
// registers nothing. A gate anchored on the condition reports a true fact about the wrong block.
const partitionMarker = "// THE ROUTE PARTITION"

// dataPlaneSymbols are the connections a control-plane deployment does not have. `dataConn` is nil
// there (ADR-0100 decision 6) and `readerConn` is nil because ADR-0094 decision 5 refuses a reader
// address outright, so either appearing in the control-plane branch is a nil dereference waiting for
// a request — and, worse, an intent to serve a route that plane must not have.
var dataPlaneSymbols = regexp.MustCompile(`\b(dataConn|readerConn)\b`)

// CheckNoDataPlaneDialInControlBranch reports every data-plane connection referenced inside the
// composition root's control-plane branch.
func CheckNoDataPlaneDialInControlBranch(mainPath string) ([]PlaneDialViolation, error) {
	body, err := os.ReadFile(mainPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", mainPath, err)
	}
	src := string(body)

	head := strings.Index(src, partitionMarker)
	if head < 0 {
		return nil, fmt.Errorf("%s has no route partition (%q): SPEC-0070 AC5/AC6 requires one, and "+
			"without it this rule has nothing to check", mainPath, partitionMarker)
	}
	rest := src[head:]
	split := strings.Index(rest, "\n\t} else {")
	if split < 0 {
		return nil, fmt.Errorf("%s: the control-plane branch has no data-plane counterpart", mainPath)
	}

	branch := rest[:split]
	lineOffset := strings.Count(src[:head], "\n")

	var out []PlaneDialViolation
	for i, line := range strings.Split(branch, "\n") {
		code := line
		if idx := strings.Index(code, "//"); idx >= 0 {
			// A comment may name the symbol — this file's own does — so only code counts. The
			// alternative is a rule that its own explanation trips, which has happened twice in
			// this tree's gates already.
			code = code[:idx]
		}
		for _, m := range dataPlaneSymbols.FindAllString(code, -1) {
			out = append(out, PlaneDialViolation{
				Symbol: m,
				Line:   lineOffset + i + 1,
				Detail: "a control-plane registration reaches a data-plane connection; that connection is " +
					"nil on this plane (ADR-0100 decision 6), and reaching for it is an intent to serve a " +
					"route ADR-0094 decision 4 keeps data-plane-side",
			})
		}
	}
	return out, nil
}
