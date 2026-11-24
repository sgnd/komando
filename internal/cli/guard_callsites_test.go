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

// reviewedCallSites is how many times the program code of internal/cli, and
// of the packages below it, calls each guard and approval function. The
// count follows a function into a package under internal/cli (the
// exported spelling counts as the same name), so a move keeps the numbers;
// a changed count is a call added or dropped, and fails here until it is
// reviewed. guardScript is counted here as calls only (five); the test where
// it is defined, TestGuardScriptCallers, counts the text "guardScript(" per
// file, which includes the declaration line and so adds one, and it pins
// which files may call it. A call moved between guard and guardScript changes
// both counts here.
var reviewedCallSites = map[string]int{
	"guard":         20,
	"guardScript":   5,
	"guardConns":    24,
	"confirmObject": 4,
	"dangerOK":      17,
	"askPerson":     2,
}

func TestGuardCallSitesAreReviewed(t *testing.T) {
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
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			// a name counts whatever the case of its first letter, so the
			// exported name a move gives it (Guard for guard) is the same call
			if _, watched := reviewedCallSites[lowerFirst(name)]; watched {
				got[lowerFirst(name)]++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
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

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func TestLowerFirst(t *testing.T) {
	for in, want := range map[string]string{"": "", "guard": "guard", "Guard": "guard", "GuardConns": "guardConns", "dangerOK": "dangerOK"} {
		if got := lowerFirst(in); got != want {
			t.Errorf("lowerFirst(%q) = %q, want %q", in, got, want)
		}
	}
}
