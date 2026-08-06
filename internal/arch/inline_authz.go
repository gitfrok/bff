package arch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// SPEC-0002 AC4: "No service performs an inline permission check that bypasses the PDP."
//
// The BFF needs this rule at least as much as the backend does, and arguably more. It has no domain
// layer to notice a stray decision, it is the layer closest to an untrusted caller, and it is
// forever one convenience away from "the frontend just needs to know if this user is an owner" —
// which is an authorization decision no matter which template consumes it.
//
// There is no equivalent of the backend's modules/policy exemption here, because there is no place
// in this repo where authorization logic is correct. The BFF asks (internal/pep) and acts on the
// answer; it never decides. That makes the rule stricter here than there, which is the right way
// round for a component invariant 18 already forbids business logic in.
//
// WHAT THIS IS, HONESTLY: a tripwire, not a proof — the same statement the backend's copy makes.
// Every other rule in this package is an import edge, which is a fact; `role == "owner"` imports
// nothing. It catches the two shapes an inline check overwhelmingly takes and cannot catch a
// sufficiently indirect one. Advertised as complete, it would be worse than absent.
//
// The duplication with the backend's copy is deliberate and unavoidable: invariant 22 forbids this
// repo from importing backend Go code, and a shared linting module would be a new cross-repo
// dependency for the sake of ~150 lines. `boundary.go` is duplicated in the same spirit.

// RuleInlinePermissionCheck fires on authorization logic anywhere in the BFF.
const RuleInlinePermissionCheck = "inline-permission-check"

// authzFuncRe matches function names that answer an authorization question. Anchored and
// case-sensitive on the noun so ordinary Go reads clean: `hasPrefix`, `canRetry` and `isReady`
// do not match; `hasPermission`, `canAccess` and `isAuthorized` do.
var authzFuncRe = regexp.MustCompile(
	`^(is|has|can|may|check|assert|require|ensure|verify|validate)` +
		`(Admin|Owner|Member|Permission|Permissions|Permitted|Authorized|Authorised|Authz|` +
		`Role|Roles|Access|Allowed|CanWrite|CanRead)`)

// authzRoleLiterals are the role names governance/policies grants against. A comparison against one
// here is the grant table reimplemented in Go, one branch at a time.
//
// Kept equal to the real vocabulary rather than widened to every plausible role word: a noisy gate
// gets waived everywhere, which is the same as being switched off.
var authzRoleLiterals = map[string]bool{
	"owner":  true,
	"member": true,
	"reader": true,
}

// authzWaiver is the escape hatch and must name a reason — a bare marker silences the gate without
// saying anything, and the reason is the part a reviewer assesses.
//
//	//arch:allow-inline-authz <why this is not an authorization decision>
var authzWaiver = regexp.MustCompile(`//arch:allow-inline-authz\s+\S+`)

// archPackageDir is this checker's own package, which necessarily contains the literals and names
// it looks for. Nothing ships from here.
const archPackageDir = "/internal/arch/"

// ScanAuthz parses file and reports inline authorization logic (SPEC-0002 AC4).
func ScanAuthz(fset *token.FileSet, file string) ([]Violation, error) {
	if strings.Contains(filepath.ToSlash(file), archPackageDir) {
		return nil, nil
	}

	f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	waived := waivedLines(fset, f)
	var vs []Violation

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Name != nil && authzFuncRe.MatchString(node.Name.Name) {
				addAuthzViolation(&vs, fset, file, node.Name.Pos(), waived, "func "+node.Name.Name)
			}
		case *ast.BinaryExpr:
			// Only equality: `role == "owner"` decides something; a map keyed by role name or a
			// sort over roles does not.
			if node.Op != token.EQL && node.Op != token.NEQ {
				return true
			}
			for _, side := range []ast.Expr{node.X, node.Y} {
				if lit := roleLiteral(side); lit != "" {
					addAuthzViolation(&vs, fset, file, node.Pos(), waived,
						"comparison against role "+strconv.Quote(lit))
					break
				}
			}
		}
		return true
	})

	return vs, nil
}

// addAuthzViolation records one hit unless its line carries a waiver.
func addAuthzViolation(vs *[]Violation, fset *token.FileSet, file string, pos token.Pos, waived map[int]bool, what string) {
	if waived[fset.Position(pos).Line] {
		return
	}
	*vs = append(*vs, Violation{File: file, Import: what, Rule: RuleInlinePermissionCheck})
}

// roleLiteral returns the role name if e is a string literal naming one, else "".
func roleLiteral(e ast.Expr) string {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil || !authzRoleLiterals[s] {
		return ""
	}
	return s
}

// waivedLines maps every line a waiver covers: its own and the next, so both the trailing and the
// comment-above forms work. Never a whole function or file — that is where a second exception
// drifts in under an allowance granted for the first.
func waivedLines(fset *token.FileSet, f *ast.File) map[int]bool {
	waived := make(map[int]bool)
	for _, group := range f.Comments {
		for _, c := range group.List {
			if !authzWaiver.MatchString(c.Text) {
				continue
			}
			line := fset.Position(c.Pos()).Line
			waived[line] = true
			waived[line+1] = true
		}
	}
	return waived
}
