package arch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SPEC-0070 AC8: a control-plane deployment holds no data-plane connection, asserted rather than
// left true by the author's care — which is the state ADR-0094 decision 7 wrote the criterion about.
func TestNoDataPlaneDialInControlBranch(t *testing.T) {
	t.Parallel()

	main := filepath.Join(repoRoot(t), "cmd", "bff", "main.go")
	violations, err := CheckNoDataPlaneDialInControlBranch(main)
	if err != nil {
		t.Fatalf("rule could not run: %v", err)
	}
	if len(violations) != 0 {
		for _, v := range violations {
			t.Errorf("control-plane branch dials the data plane: %s", v)
		}
	}
}

// The rule must be failable, and by the same code path the real source takes. A gate nobody has
// seen fail is a gate nobody has tested — this tree has had two that passed only because their
// assertion was tripping over its own comment.
func TestPlaneDialRuleCatchesAViolation(t *testing.T) {
	t.Parallel()

	fixture := placeMainFixture(t, "main_with_dial.go.txt")
	violations, err := CheckNoDataPlaneDialInControlBranch(fixture)
	if err != nil {
		t.Fatalf("rule could not run against the fixture: %v", err)
	}
	if len(violations) == 0 {
		t.Fatal("the fixture registers a control-plane route on dataConn and the rule accepted it")
	}
	if !strings.Contains(violations[0].Symbol, "dataConn") {
		t.Errorf("violation does not name the connection: %+v", violations[0])
	}
}

// A file with no partition is an error rather than a pass. Returning "no violations" for a
// composition root that has lost its partition would report success for the worst case.
func TestPlaneDialRuleRefusesAMissingPartition(t *testing.T) {
	t.Parallel()

	empty := filepath.Join(t.TempDir(), "main.go")
	if err := writeFile(empty, "package main\n\nfunc main() {}\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckNoDataPlaneDialInControlBranch(empty); err == nil {
		t.Error("a composition root with no route partition was accepted; SPEC-0070 AC5/AC6 requires one")
	}
}

// placeMainFixture copies a composition-root fixture to a temp path. It does not reuse
// placeFixture, which builds a package directory for the import-boundary rules — this rule reads a
// single file, and bending that helper to serve both would make each harder to read.
func placeMainFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	path := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}
