package arch

import (
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestNoInlinePermissionChecks is the SPEC-0002 AC4 fitness function for the BFF: no file in this
// repo decides access. It asks the PDP through internal/pep, or it does not ask at all.
func TestNoInlinePermissionChecks(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var found []Violation

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "gen", "testdata", "node_modules", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		vs, err := ScanAuthz(fset, path)
		if err != nil {
			return err
		}
		found = append(found, vs...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range found {
		t.Errorf("inline permission check: %s: %s (%s) — the BFF asks the PDP, it never decides "+
			"(invariants 2 and 18). If this genuinely grants no access, waive the line with "+
			"//arch:allow-inline-authz <reason>", v.File, v.Import, v.Rule)
	}
}

// TestInlinePermissionChecksAreRejected: without this the tree scan above would pass vacuously if
// the matcher were broken — the reverse test every rule in this package carries.
func TestInlinePermissionChecksAreRejected(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    string
	}{
		{"bad_inline_authz_func.go.txt", "func hasPermission"},
		{"bad_inline_authz_role.go.txt", `comparison against role "owner"`},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			vs, err := ScanAuthz(token.NewFileSet(), placeFixture(t, tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if len(vs) == 0 {
				t.Fatalf("%s produced no violation; the gate is vacuous", tc.fixture)
			}
			var got []string
			for _, v := range vs {
				if v.Rule != RuleInlinePermissionCheck {
					t.Errorf("rule = %q, want %q", v.Rule, RuleInlinePermissionCheck)
				}
				got = append(got, v.Import)
			}
			if !slices.Contains(got, tc.want) {
				t.Errorf("violations %v, want one naming %q", got, tc.want)
			}
		})
	}
}

// The other half, which matters as much: a rule that fires on correct code gets waived everywhere,
// and a rule waived everywhere is off.
func TestLegitimateCodeIsNotRejected(t *testing.T) {
	for _, fixture := range []string{
		"good_authz_via_pep.go.txt",
		"good_ordinary_names.go.txt",
		"good_inline_authz_waived.go.txt",
		// The pre-existing boundary fixture, included so this rule is shown not to fire on the
		// ordinary handler code the other rules were written against.
		"good_handler.go.txt",
	} {
		t.Run(fixture, func(t *testing.T) {
			vs, err := ScanAuthz(token.NewFileSet(), placeFixture(t, fixture))
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range vs {
				t.Errorf("false positive: %s flagged %q", fixture, v.Import)
			}
		})
	}
}

// A waiver covers one line. If it covered a function or a file, the second inline check would drift
// in under an exception granted for the first and nobody would see it.
func TestWaiverDoesNotCoverTheRestOfTheFile(t *testing.T) {
	vs := scanSource(t, `package fixture

func label(role string) string {
	//arch:allow-inline-authz display label only
	if role == "owner" {
		return "Owner"
	}
	// No waiver here.
	if role == "member" {
		return "Member"
	}
	return role
}
`)
	if len(vs) != 1 {
		t.Fatalf("got %d violations %v, want exactly 1", len(vs), vs)
	}
	if !strings.Contains(vs[0].Import, "member") {
		t.Errorf("violation %q, want the unwaived \"member\" comparison", vs[0].Import)
	}
}

// A bare marker must not silence the rule: the reason is the part review assesses.
func TestWaiverWithoutAReasonDoesNotCount(t *testing.T) {
	vs := scanSource(t, `package fixture

func label(role string) string {
	//arch:allow-inline-authz
	if role == "owner" {
		return "Owner"
	}
	return role
}
`)
	if len(vs) != 1 {
		t.Errorf("got %d violations, want 1: a waiver with no reason must not count", len(vs))
	}
}

// Unlike the backend, this repo has no exempt package — there is nowhere in the BFF where deciding
// access is correct.
func TestNoPackageIsExemptFromTheRule(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("testdata", "bad_inline_authz_role.go.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"internal/pep", "internal/aggregate", "cmd/bff"} {
		t.Run(dir, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), filepath.FromSlash(dir))
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, "fixture.go")
			if err := os.WriteFile(file, content, 0o644); err != nil {
				t.Fatal(err)
			}
			vs, err := ScanAuthz(token.NewFileSet(), file)
			if err != nil {
				t.Fatal(err)
			}
			if len(vs) == 0 {
				t.Errorf("%s was exempted; no package in this repo may decide access", dir)
			}
		})
	}
}

func scanSource(t *testing.T, src string) []Violation {
	t.Helper()
	file := filepath.Join(t.TempDir(), "fixture.go")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	vs, err := ScanAuthz(token.NewFileSet(), file)
	if err != nil {
		t.Fatal(err)
	}
	return vs
}
