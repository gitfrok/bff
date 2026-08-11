// Package arch holds the BFF's boundary fitness functions (T-0002 AC3). The BFF aggregates and
// shapes only (invariant 18): it reaches backend over gRPC using the generated contracts, and
// never imports backend Go code. Enforced here rather than by review discipline.
package arch

import (
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
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
	// RuleDirectDataStore fires when the BFF opens a datastore itself. T-0002 deferred this rule
	// to T-0009 rather than widening its own criteria; it lands here.
	RuleDirectDataStore = "bff-direct-datastore"
)

// dataStoreMarkers are import substrings that mean this process is talking to a datastore.
//
// The BFF has almost no data of its own: every context owns its schema and is reached through its
// API (invariant 15). A query from here would also run outside RLS and without a PDP decision, so
// one convenient join breaks tenancy and authorization at the same time (invariants 1, 2) — and it
// would do so in the one component with no domain layer to notice.
//
// Cache and message clients are listed alongside SQL drivers deliberately: reading another
// context's state out of Valkey or consuming its topic directly is the same coupling wearing a
// different protocol. gRPC is absent because that is the sanctioned transport.
//
// The one exception is the browser session store — see sessionStoreWaiver below and ADR-0052.
var dataStoreMarkers = []string{
	"database/sql", "jackc/pgx", "lib/pq", "go-sql-driver/mysql", "mattn/go-sqlite3",
	"jmoiron/sqlx", "gorm.io", "ent.io", "uptrace/bun",
	"valkey-io/valkey-go", "redis/go-redis", "gomodule/redigo",
	"twmb/franz-go", "confluentinc/confluent-kafka-go", "segmentio/kafka-go",
}

var backendInternalRe = regexp.MustCompile(
	`^` + regexp.QuoteMeta(BackendModulePath) + `/(modules/[^/]+/)?internal(/|$)`)

// ADR-0052: the BFF may open exactly one datastore — the browser session store ADR-0049 decides —
// and the exemption is declared in the source rather than inferred.
//
// A session is the BFF's *own* state, not a projection of another context's data: the record holds
// what the BFF minted at the OIDC callback and nothing another context owns, so resolving it is not
// the cross-context read invariant 15 forbids. That is the whole of the argument, and it does not
// extend one line further — a read of another context's state through this client is still a
// violation, whatever file it sits in.
//
// Both conditions below are required. The path alone would let a future file inherit the exemption
// by sitting in the right directory; the marker alone would let it be pasted into a handler.
const (
	// sessionStoreDir is the only directory a datastore import may appear in, and it is matched as
	// the file's immediate parent rather than as a substring: `internal/session/replica/` is a
	// different package, and ADR-0052 exempts one flat, reviewable location — not a subtree.
	sessionStoreDir = "internal/session"
	// RuleSessionStoreWaiverOutsidePackage fires when the waiver is used anywhere else. A marker
	// that silently did nothing would be worse than one that fails: the author believed it worked.
	RuleSessionStoreWaiverOutsidePackage = "session-store-waiver-outside-session-package"
)

// sessionStoreWaiver must name a reason. A bare marker silences the gate without saying anything,
// and the reason is the part a reviewer assesses.
//
//	//arch:allow-session-store <why this is the BFF's own state>
var sessionStoreWaiver = regexp.MustCompile(`//arch:allow-session-store\s+\S+`)

// Violation is one broken architecture rule at a source location.
type Violation struct {
	File   string
	Import string
	Rule   string
}

// anImport is one import path and the line it sits on. The line is what a waiver is scoped to.
type anImport struct {
	path string
	line int
}

// importsOf parses a single Go source file and returns its imports and the lines any session-store
// waiver covers. Comments are parsed rather than skipped because the waiver is a comment.
func importsOf(fset *token.FileSet, path string) ([]anImport, map[int]bool, error) {
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.ParseComments)
	if err != nil {
		return nil, nil, err
	}
	out := make([]anImport, 0, len(f.Imports))
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		out = append(out, anImport{path: p, line: fset.Position(spec.Pos()).Line})
	}

	// Its own line and the next, so both the trailing and the comment-above forms work. Never a
	// whole file — that is where a second exception drifts in under an allowance granted for the
	// first.
	waived := make(map[int]bool)
	for _, group := range f.Comments {
		for _, c := range group.List {
			if !sessionStoreWaiver.MatchString(c.Text) {
				continue
			}
			line := fset.Position(c.Pos()).Line
			waived[line] = true
			waived[line+1] = true
		}
	}
	return out, waived, nil
}

// checkFile applies the BFF boundary rules to one file's imports.
func checkFile(file string, imports []anImport, waived map[int]bool) []Violation {
	inSessionPackage := strings.HasSuffix(path.Dir(filepath.ToSlash(file)), sessionStoreDir)

	// A waiver outside internal/session/ is reported even when nothing else is wrong: the author
	// wrote it believing it granted something, and it does not.
	if len(waived) > 0 && !inSessionPackage {
		vs := []Violation{{File: file, Import: "//arch:allow-session-store", Rule: RuleSessionStoreWaiverOutsidePackage}}
		return append(vs, checkImports(file, imports, nil)...)
	}
	return checkImports(file, imports, waived)
}

// checkImports is the per-import half, with waived holding the lines a session-store waiver covers.
func checkImports(file string, imports []anImport, waived map[int]bool) []Violation {
	var vs []Violation
	for _, im := range imports {
		imp := im.path
		if isDataStore(imp) && !waived[im.line] {
			vs = append(vs, Violation{File: file, Import: imp, Rule: RuleDirectDataStore})
		}
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

// isDataStore reports whether an import path opens a datastore connection.
func isDataStore(imp string) bool {
	for _, marker := range dataStoreMarkers {
		if strings.Contains(imp, marker) {
			return true
		}
	}
	return false
}

// isBackendImport reports whether an import path resolves into the backend Go module. The trailing
// separator check keeps a same-prefix module such as ".../backend-tools" from matching.
func isBackendImport(imp string) bool {
	return imp == BackendModulePath || strings.HasPrefix(imp, BackendModulePath+"/")
}

// Scan parses a Go source file and returns any boundary violations. Callers pass one file at a
// time so fixtures (kept outside the build tree) are checked identically to real code.
func Scan(fset *token.FileSet, file string) ([]Violation, error) {
	imports, waived, err := importsOf(fset, file)
	if err != nil {
		return nil, err
	}
	return checkFile(file, imports, waived), nil
}
