package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// reviewedCallSites is how many times the program code of internal/cli calls
// each guard and approval function today. A move that takes these calls to
// another package updates the numbers on purpose; a change to the count
// without that is a call added or dropped, and fails here until it is
// reviewed. guardScript is not here: its callers have their own test where
// it is defined.
var reviewedCallSites = map[string]int{
	"guard":         25,
	"guardConns":    24,
	"confirmObject": 4,
	"dangerOK":      17,
	"askPerson":     2,
}

func TestGuardCallSitesAreReviewed(t *testing.T) {
	got := map[string]int{}
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				if _, watched := reviewedCallSites[fn.Name]; watched {
					got[fn.Name]++
				}
			case *ast.SelectorExpr:
				if _, watched := reviewedCallSites[fn.Sel.Name]; watched {
					got[fn.Sel.Name]++
				}
			}
			return true
		})
	}
	var names []string
	for n := range reviewedCallSites {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if got[n] != reviewedCallSites[n] {
			t.Errorf("%s is called %d times in the program code, the reviewed count is %d: review the change, then update reviewedCallSites", n, got[n], reviewedCallSites[n])
		}
	}
}
