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
	"guard":         22, // -1 reboot (C493): exec rule power, TestRulePower; +1 deviceKeyInstall (key_revoke.go): a phone's key on one server, C372
	"guardScript":   5,
	"guardConns":    25, // +1 snippetTierStop (recipe.go): a dangerous built-in snippet, C368 S1-1
	"confirmObject": 4,
<<<<<<< HEAD
	"dangerOK":      17, // 16 commands (-1 reboot, C493: TestRulePower), and (*call).dangerOK forwarding to (*gate).dangerOK (C468)
	"askPerson":     2,
=======
	"dangerOK":      18, // 17 commands, and (*call).dangerOK forwarding to (*gate).dangerOK (C468)
	"askPerson":     3,  // the third: the window of the move to format 3 (migrateCallFor)
>>>>>>> feat/c489-cut-e1-format3
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
// cli's readAnswer, which calls noteAsk first. Any other reference fails
// here: a call, a function value, or a dot-imported name.
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
		// in kit/term itself, or after a dot import, the name stands alone
		bare := termNames["."] || file.Name.Name == "term" && strings.HasSuffix(filepath.ToSlash(filepath.Dir(p)), "internal/cli/kit/term")
		for _, decl := range file.Decls {
			where := "(package level)"
			var node ast.Node = decl
			fn, isFunc := decl.(*ast.FuncDecl)
			if isFunc {
				if fn.Body == nil {
					continue
				}
				where, node = fn.Name.Name, fn.Body // not its own name
			}
			// every reference counts, not only a call: a function value
			// (f := term.ReadAnswer) would be a call that skips noteAsk
			var visit func(ast.Node) bool
			visit = func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.SelectorExpr:
					if x, ok := e.X.(*ast.Ident); ok && termNames[x.Name] && e.Sel.Name == "ReadAnswer" {
						callers = append(callers, filepath.ToSlash(p)+": "+where)
					}
					ast.Inspect(e.X, visit)
					return false // e.Sel alone is a field or method name, not this function
				case *ast.Ident:
					if bare && e.Name == "ReadAnswer" {
						callers = append(callers, filepath.ToSlash(p)+": "+where)
					}
				}
				return true
			}
			ast.Inspect(node, visit)
			if !isFunc {
				continue
			}
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
		t.Errorf("term.ReadAnswer is named in:\n%s\nwant only in cli's readAnswer, which calls noteAsk first", strings.Join(callers, "\n"))
	}
	if !firstIsNoteAsk {
		t.Error("cli's readAnswer must call noteAsk before anything else")
	}
}
