package arch

import (
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot returns the bff module root (two levels up from internal/arch).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// TestNoBoundaryViolations is the fitness function for T-0002 AC3: no file in this repo may import
// backend Go code. The BFF aggregates over gRPC using generated contracts (invariants 18, 22).
func TestNoBoundaryViolations(t *testing.T) {
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
		vs, err := Scan(fset, path)
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
		t.Errorf("boundary violation: %s imports %s (%s)", v.File, v.Import, v.Rule)
	}
}

// placeFixture writes a testdata fixture into a temp tree and returns its path, so a forbidden
// edge is checked through exactly the same code path as real source.
func placeFixture(t *testing.T, fixture string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "internal", "handler")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "fixture.go")
	if err := os.WriteFile(file, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestForbiddenEdgesAreRejected proves each forbidden import is caught, so the tree scan above
// cannot pass vacuously if the checker breaks.
func TestForbiddenEdgesAreRejected(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		want    []string
	}{
		{
			name:    "AC3 backend module internal",
			fixture: "bad_backend_module_internal.go.txt",
			want:    []string{RuleBackendInternalImport, RuleBackendImport},
		},
		{
			name:    "AC3 backend repo-level internal",
			fixture: "bad_backend_repo_internal.go.txt",
			want:    []string{RuleBackendInternalImport, RuleBackendImport},
		},
		{
			// A module's public api/ is an in-process surface for other backend modules only.
			name:    "backend module api is still off limits",
			fixture: "bad_backend_api.go.txt",
			want:    []string{RuleBackendImport},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vs, err := Scan(token.NewFileSet(), placeFixture(t, tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !hasRule(vs, want) {
					t.Errorf("expected rule %q to fire, got %v", want, vs)
				}
			}
		})
	}
}

// TestLegitimateCodeIsAccepted guards against a checker so blunt it blocks the BFF's actual shape:
// standard library, gRPC as transport, and this repo's own generated contracts.
func TestLegitimateCodeIsAccepted(t *testing.T) {
	vs, err := Scan(token.NewFileSet(), placeFixture(t, "good_handler.go.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 0 {
		t.Errorf("expected no violations, got %v", vs)
	}
}

// TestSimilarlyNamedModuleIsNotMatched pins the prefix check: a different module that merely
// starts with the backend path must not be flagged.
func TestSimilarlyNamedModuleIsNotMatched(t *testing.T) {
	if isBackendImport("github.com/gitfrok/backend-tools/pkg/util") {
		t.Error("backend-tools must not match the backend module path")
	}
	if !isBackendImport(BackendModulePath) {
		t.Error("the backend module path itself must match")
	}
}

func hasRule(vs []Violation, rule string) bool {
	for _, v := range vs {
		if v.Rule == rule {
			return true
		}
	}
	return false
}
