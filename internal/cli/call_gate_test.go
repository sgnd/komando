package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// gateFlagNames are the four global flags that decide the safety gate:
// what runs (--dry-run), what a person confirmed (--yes), what the safety
// rules let through (--allow-dangerous) and what output shows (--reveal).
var gateFlagNames = map[string]bool{"dryRun": true, "yes": true, "allowDangerous": true, "reveal": true}

// programGateWriters is every place the program code of internal/cli writes
// a gate flag (x.flags.dryRun ...), the whole flags of a call (x.flags), or
// sets who is calling (setCaller): cobra binds the four flags to the call
// and newRoot resets them, kctl's diff turns --dry-run on for the length of
// one apply, begin reads the caller from the call's environment, and the
// ssh gate's shell makes its key's commands an agent's. A new writer fails
// here until it is reviewed: it could turn --yes or --allow-dangerous on
// for a command the person never confirmed.
var programGateWriters = map[string]int{
	"cluster_kctl_change.go r.cl.flags.dryRun": 2,
	"root.go &cl.flags.allowDangerous":         1,
	"root.go &cl.flags.dryRun":                 1,
	"root.go &cl.flags.reveal":                 1,
	"root.go &cl.flags.yes":                    1,
	"root.go cl.flags":                         1,
	"call.go setCaller":                        1,
	"sshgate_shell.go setCaller":               1,
}

func TestGateWritersAreReviewed(t *testing.T) {
	got := gateWriters(t, false)
	if !maps.Equal(got, programGateWriters) {
		t.Errorf("the program code writes the gate flags or the caller at:\n%s\nwant:\n%s\na new or moved writer needs a review: it decides what komando lets through", writerLines(got), writerLines(programGateWriters))
	}
}

// gateWriters counts, per file and expression, the writes of a gate flag,
// of a call's whole flags and the setCaller calls in the program files
// (tests false) or the test files (tests true) of internal/cli and the
// packages below it. A write is an assignment or taking the address (a
// flag binding writes through it).
func gateWriters(t *testing.T, tests bool) map[string]int {
	t.Helper()
	got := map[string]int{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") != tests {
			return nil
		}
		file, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(p)
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, l := range n.Lhs {
					if gateTarget(l) {
						got[name+" "+types.ExprString(ast.Unparen(l))]++
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND && gateTarget(n.X) {
					got[name+" &"+types.ExprString(ast.Unparen(n.X))]++
				}
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "setCaller" {
					got[name+" setCaller"]++
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// gateTarget reports whether e is a call's gate flag (x.flags.yes ...) or
// its whole flags (x.flags).
func gateTarget(e ast.Expr) bool {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if sel.Sel.Name == "flags" {
		return true
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	return ok && inner.Sel.Name == "flags" && gateFlagNames[sel.Sel.Name]
}

// writerLines is m as sorted "file expression: count" lines.
func writerLines(m map[string]int) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(m)) {
		b.WriteString("  " + k + ": " + strconv.Itoa(m[k]) + "\n")
	}
	return b.String()
}
