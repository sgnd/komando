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

// term.ReadAnswer reads a person's answer at the terminal. The guard counts
// every such question (noteAsk), so the program reaches it only through
// cli's readAnswer, which calls noteAsk first. A new caller fails here.
func TestReadAnswerOnlyThroughTheWrapper(t *testing.T) {
	const termPath = "github.com/sgnd/komando/internal/cli/kit/term"
	var callers []string
	firstIsNoteAsk := false
	fset := token.NewFileSet()
	err := filepath.WalkDir("../..", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") && p != "../.." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		termNames := map[string]bool{}
		for _, imp := range file.Imports {
			if strings.Trim(imp.Path.Value, `"`) == termPath {
				name := "term"
				if imp.Name != nil {
					name = imp.Name.Name
				}
				termNames[name] = true
			}
		}
		inTerm := file.Name.Name == "term" && strings.HasSuffix(filepath.ToSlash(filepath.Dir(p)), "internal/cli/kit/term")
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch f := call.Fun.(type) {
				case *ast.SelectorExpr:
					if x, ok := f.X.(*ast.Ident); ok && termNames[x.Name] && f.Sel.Name == "ReadAnswer" {
						callers = append(callers, filepath.ToSlash(p)+": "+fn.Name.Name)
					}
				case *ast.Ident:
					if inTerm && f.Name == "ReadAnswer" {
						callers = append(callers, filepath.ToSlash(p)+": "+fn.Name.Name)
					}
				}
				return true
			})
			if fn.Name.Name == "readAnswer" && file.Name.Name == "cli" && len(fn.Body.List) > 0 {
				if es, ok := fn.Body.List[0].(*ast.ExprStmt); ok {
					if c, ok := es.X.(*ast.CallExpr); ok {
						if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "noteAsk" {
							firstIsNoteAsk = true
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"../../internal/cli/ttyin.go: readAnswer"}; strings.Join(callers, "\n") != strings.Join(want, "\n") {
		t.Errorf("term.ReadAnswer is called from:\n%s\nwant only from cli's readAnswer, which calls noteAsk first", strings.Join(callers, "\n"))
	}
	if !firstIsNoteAsk {
		t.Error("cli's readAnswer must call noteAsk before anything else")
	}
}
