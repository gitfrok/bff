// Package arch holds the BFF's boundary fitness functions (T-0002 AC3). The BFF aggregates and
// shapes only (invariant 18): it reaches backend over gRPC using the generated contracts, and
// never imports backend Go code. Enforced here rather than by review discipline.
package arch

import (
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// BackendModulePath is the backend repo's Go module path. Per invariant 22 and ADR-0027 the only
// shared surface between these repos is governance/contracts/ (vendored per-repo under gen/), so
// the BFF must not import this module at all.
const BackendModulePath = "github.com/gitfrok/backend"

// Rule names. Stable strings: CI output and the fixtures in testdata both key off them.
const (
	// RuleBackendInternalImport fires when the BFF reaches into a backend module's internal/* —
	// the case T-0002 AC3 names explicitly.
	RuleBackendInternalImport = "bff-imports-backend-internal"
	// RuleBackendImport fires on any import of the backend Go module. The BFF talks to backend
	// over gRPC only; a compile-time edge in either direction violates invariant 22.
	RuleBackendImport = "bff-imports-backend"
)

var backendInternalRe = regexp.MustCompile(
	`^` + regexp.QuoteMeta(BackendModulePath) + `/(modules/[^/]+/)?internal(/|$)`)

// Violation is one broken architecture rule at a source location.
type Violation struct {
	File   string
	Import string
	Rule   string
}

// importsOf parses a single Go source file and returns its import paths.
func importsOf(fset *token.FileSet, path string) ([]string, error) {
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(f.Imports))
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// checkFile applies the BFF boundary rules to one file's imports.
func checkFile(file string, imports []string) []Violation {
	var vs []Violation
	for _, imp := range imports {
		if !isBackendImport(imp) {
			continue
		}
		// Report the specific rule first so CI output names the sharper violation, then the
		// general one: an internal import breaks both AC3 and the dependency direction.
		if backendInternalRe.MatchString(imp) {
			vs = append(vs, Violation{File: file, Import: imp, Rule: RuleBackendInternalImport})
		}
		vs = append(vs, Violation{File: file, Import: imp, Rule: RuleBackendImport})
	}
	return vs
}

// isBackendImport reports whether an import path resolves into the backend Go module. The trailing
// separator check keeps a same-prefix module such as ".../backend-tools" from matching.
func isBackendImport(imp string) bool {
	return imp == BackendModulePath || strings.HasPrefix(imp, BackendModulePath+"/")
}

// Scan parses a Go source file and returns any boundary violations. Callers pass one file at a
// time so fixtures (kept outside the build tree) are checked identically to real code.
func Scan(fset *token.FileSet, file string) ([]Violation, error) {
	imports, err := importsOf(fset, file)
	if err != nil {
		return nil, err
	}
	return checkFile(file, imports), nil
}
