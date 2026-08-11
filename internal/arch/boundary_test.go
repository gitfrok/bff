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
	return placeFixtureIn(t, fixture, "handler")
}

// placeFixtureIn is placeFixture with the package directory chosen, because ADR-0052's session-store
// waiver is scoped by path: the same source is legal under internal/session/ and illegal elsewhere,
// and only a real path can prove it.
func placeFixtureIn(t *testing.T, fixture, pkgDir string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "internal", pkgDir)
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
		{
			name:    "direct SQL through a driver",
			fixture: "bad_direct_db.go.txt",
			want:    []string{RuleDirectDataStore},
		},
		{
			name:    "direct SQL through the standard library",
			fixture: "bad_database_sql.go.txt",
			want:    []string{RuleDirectDataStore},
		},
		{
			name:    "reaching the shared cache sideways",
			fixture: "bad_valkey_cache.go.txt",
			want:    []string{RuleDirectDataStore},
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

// TestSessionStoreWaiverIsPathScoped is ADR-0052's whole guarantee: the exemption needs the marker
// AND the package, so it can be neither inherited by location nor pasted into a handler.
func TestSessionStoreWaiverIsPathScoped(t *testing.T) {
	t.Run("waived inside internal/session is allowed", func(t *testing.T) {
		vs, err := Scan(token.NewFileSet(), placeFixtureIn(t, "good_session_store_waived.go.txt", "session"))
		if err != nil {
			t.Fatal(err)
		}
		if len(vs) != 0 {
			t.Errorf("the session store is ADR-0052's one exception, got %v", vs)
		}
	})

	t.Run("unwaived inside internal/session still fires", func(t *testing.T) {
		vs, err := Scan(token.NewFileSet(), placeFixtureIn(t, "bad_session_store_unwaived.go.txt", "session"))
		if err != nil {
			t.Fatal(err)
		}
		if !hasRule(vs, RuleDirectDataStore) {
			t.Errorf("the path alone must grant nothing, got %v", vs)
		}
	})

	t.Run("a subdirectory of internal/session does not inherit the waiver", func(t *testing.T) {
		vs, err := Scan(token.NewFileSet(), placeFixtureIn(t, "good_session_store_waived.go.txt", filepath.Join("session", "replica")))
		if err != nil {
			t.Fatal(err)
		}
		if !hasRule(vs, RuleDirectDataStore) {
			t.Errorf("ADR-0052 exempts one package, not a subtree, got %v", vs)
		}
	})

	t.Run("the waiver outside internal/session is itself a violation", func(t *testing.T) {
		vs, err := Scan(token.NewFileSet(), placeFixtureIn(t, "bad_session_store_waiver_in_handler.go.txt", "handler"))
		if err != nil {
			t.Fatal(err)
		}
		if !hasRule(vs, RuleSessionStoreWaiverOutsidePackage) {
			t.Errorf("a marker that grants nothing must say so, got %v", vs)
		}
		if !hasRule(vs, RuleDirectDataStore) {
			t.Errorf("the import it tried to cover must still fire, got %v", vs)
		}
	})
}

// TestSessionStoreWaiverNeedsAReason pins the reason requirement: a bare marker silences the gate
// without saying anything, and the reason is what a reviewer assesses.
func TestSessionStoreWaiverNeedsAReason(t *testing.T) {
	if sessionStoreWaiver.MatchString("//arch:allow-session-store") {
		t.Error("a bare marker must not waive anything")
	}
	if !sessionStoreWaiver.MatchString("//arch:allow-session-store ADR-0052 — the BFF's own state") {
		t.Error("a marker with a reason must waive")
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

// TestGRPCIsNotADataStore pins the line the datastore rule must not cross: gRPC is the sanctioned
// transport to backend, so a checker that flagged it would forbid the BFF's whole job.
func TestGRPCIsNotADataStore(t *testing.T) {
	allowed := []string{
		"google.golang.org/grpc",
		"google.golang.org/protobuf/proto",
		"github.com/gitfrok/bff/gen/proto/agent/v1",
		"net/http",
		"context",
	}
	for _, imp := range allowed {
		if isDataStore(imp) {
			t.Errorf("%q must not be treated as a datastore", imp)
		}
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
