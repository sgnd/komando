package testhome

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// repoRoot is the repository's folder (this package is internal/testhome).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(filepath.Dir(wd))
}

// goDirs lists the folders under root that hold Go files, with their files.
func goDirs(t *testing.T, root string) map[string][]string {
	t.Helper()
	dirs := map[string][]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); p != root && (strings.HasPrefix(n, ".") || n == "testdata" || n == "bin" || n == "dist" || n == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") {
			dirs[filepath.Dir(p)] = append(dirs[filepath.Dir(p)], p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

// homeWords are how Go code names a home folder.
// komando's own data folder counts: store.Home and store.Path are in it,
// and store.Load and store.Update open the store there.
var homeWords = []string{"UserHomeDir", "UserConfigDir", "UserCacheDir", `"HOME"`, `"USERPROFILE"`, `"APPDATA"`, `"LOCALAPPDATA"`, `"XDG_`,
	"user.Current(", "$HOME", `"~/`, "store.Home(", "store.Path(", "store.UserHome(", "store.AccountHome(", "store.Load(", "store.Update(", "vault.Get(", "vault.Set("}

// Every package whose code names a home folder, and that has tests,
// starts them with Use in a TestMain: all its tests get the throwaway
// home, whatever each one sets up itself.
func TestPackagesThatNameAHomeUseTheThrowawayOne(t *testing.T) {
	root := repoRoot(t)
	seen := 0
	defer func() {
		if seen < 8 {
			t.Errorf("only %d packages name a home folder: the rule is looking in the wrong place (%s)", seen, root)
		}
	}()
	for dir, files := range goDirs(t, root) {
		rel, _ := filepath.Rel(root, dir)
		if rel == filepath.Join("internal", "testhome") || strings.HasPrefix(rel, "sync") {
			continue // this package; sync/ is a module of its own (it names no home)
		}
		names, tests, uses := false, false, false
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			s := string(b)
			if strings.HasSuffix(f, "_test.go") {
				tests = true
				uses = uses || callsUse(t, f)
			}
			// the package's own code decides: a test's shell text
			// (`echo $HOME`) reads no home folder
			names = names || (!strings.HasSuffix(f, "_test.go") && slices.ContainsFunc(homeWords, func(w string) bool { return strings.Contains(s, w) }))
		}
		if names && tests {
			seen++
		}
		if names && tests && !uses {
			t.Errorf("%s names a home folder (os.UserHomeDir, HOME, APPDATA, XDG_...) but its tests have no TestMain that calls testhome.Use()", rel)
		}
	}
}

// callsUse reports whether the test file has a TestMain whose code calls
// testhome.Use (a comment that says so does not count).
func callsUse(t *testing.T, path string) bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "TestMain" || fn.Recv != nil || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && isCall(c, "testhome", "Use") {
				found = true
			}
			return !found
		})
	}
	return found
}

// writers are the os functions that make, change or remove a file, with
// the positions of their path arguments.
var writers = map[string][]int{
	"WriteFile": {0}, "MkdirAll": {0}, "Mkdir": {0}, "Create": {0}, "OpenFile": {0}, "Remove": {0}, "RemoveAll": {0},
	"Rename": {0, 1}, "Symlink": {1}, "Link": {1}, "Chmod": {0}, "Truncate": {0}, "Chtimes": {0},
	"Chown": {0}, "Lchown": {0}, "CreateTemp": {0}, "MkdirTemp": {0},
}

// homeCalls are the calls that give a path in a home folder. komando's
// own data folder (store.Home, store.Path) is left out: tests give it a
// temp folder of their own, and without one it lies in the throwaway home.
var homeCalls = [][2]string{
	{"os", "UserHomeDir"}, {"os", "UserConfigDir"}, {"os", "UserCacheDir"}, {"user", "Current"},
	{"store", "UserHome"}, {"store", "AccountHome"}, {"testhome", "Real"},
}

// No test writes to a path built from the home folder (os.UserHomeDir, the
// HOME variable, a "~/..." text) unless the path
// went through testhome.Path, which fails the test for a path outside the
// throwaway home. The check follows names inside one function:
// p := filepath.Join(home, ...). It is a tripwire for the plain mistake,
// not a proof: a path handed through a helper, a struct field or one of
// komando's own commands is not followed. What keeps such a write out of
// the real home is Use, which every package that names a home must call.
func TestTestsWriteHomePathsOnlyThroughPath(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	for _, files := range goDirs(t, root) {
		for _, f := range files {
			if !strings.HasSuffix(f, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(root, f)
			for _, bad := range homeWrites(fset, file) {
				t.Errorf("%s:%s: wrap the path in testhome.Path(t, ...)", rel, bad)
			}
		}
	}
}

// homeWrites lists the writer calls in file whose path comes from a home
// folder and is not wrapped in testhome.Path, as "LINE: os.Func(...)".
func homeWrites(fset *token.FileSet, file *ast.File) []string {
	var bad []string
	for _, decl := range file.Decls {
		// one scope per top-level declaration: a function, or the
		// functions written into a package-level var
		var body ast.Node = decl
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if fn.Body == nil {
				continue
			}
			body = fn.Body
		}
		tainted := map[string]bool{}
		fromHome := func(e ast.Expr) bool {
			hit := false
			ast.Inspect(e, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if isCall(x, "testhome", "Path") {
						return false // checked when the test runs
					}
					if slices.ContainsFunc(homeCalls, func(c [2]string) bool { return isCall(x, c[0], c[1]) }) {
						hit = true
					}
					if (isCall(x, "os", "Getenv") || isCall(x, "os", "LookupEnv")) && len(x.Args) == 1 {
						if lit, ok := x.Args[0].(*ast.BasicLit); ok {
							if v, _ := strconv.Unquote(lit.Value); v == "HOME" || v == "USERPROFILE" || v == "APPDATA" || v == "LOCALAPPDATA" || strings.HasPrefix(v, "XDG_") {
								hit = true
							}
						}
					}
				case *ast.BasicLit:
					if x.Kind == token.STRING {
						if v, _ := strconv.Unquote(x.Value); v == "~" || strings.HasPrefix(v, "~/") || strings.HasPrefix(v, `~\`) || strings.Contains(v, "$HOME") || strings.Contains(v, "${HOME}") {
							hit = true
						}
					}
				case *ast.Ident:
					if tainted[x.Name] {
						hit = true
					}
				}
				return !hit
			})
			return hit
		}
		// names that hold a home path: assigned from one, until nothing new
		for changed := true; changed; {
			changed = false
			ast.Inspect(body, func(n ast.Node) bool {
				if vs, ok := n.(*ast.ValueSpec); ok { // var key = filepath.Join(home, ...)
					for i, v := range vs.Values {
						if !fromHome(v) {
							continue
						}
						names := vs.Names[:1]
						if len(vs.Values) == len(vs.Names) {
							names = vs.Names[i : i+1]
						}
						for _, id := range names {
							if id.Name != "_" && !tainted[id.Name] {
								tainted[id.Name] = true
								changed = true
							}
						}
					}
					return true
				}
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, rhs := range as.Rhs {
					if !fromHome(rhs) {
						continue
					}
					lhs := as.Lhs[:1] // d, err := os.UserHomeDir()
					if len(as.Rhs) == len(as.Lhs) {
						lhs = as.Lhs[i : i+1]
					}
					for _, l := range lhs {
						if id, ok := l.(*ast.Ident); ok && id.Name != "_" && !tainted[id.Name] {
							tainted[id.Name] = true
							changed = true
						}
					}
				}
				return true
			})
		}
		ast.Inspect(body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" {
				return true
			}
			for _, i := range writers[sel.Sel.Name] {
				if i < len(call.Args) && fromHome(call.Args[i]) {
					bad = append(bad, strconv.Itoa(fset.Position(call.Pos()).Line)+": os."+sel.Sel.Name+" writes to a path from the home folder")
				}
			}
			return true
		})
	}
	return bad
}

func isCall(c *ast.CallExpr, pkg, name string) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// The walker itself: it sees a home path through a second name, and
// leaves alone what went through Path or never came from a home.
func TestHomeWritesWalker(t *testing.T) {
	src := `package x
import ("os"; "path/filepath"; "testing"; "github.com/sgnd/komando/internal/testhome")
func TestA(t *testing.T) {
	home, _ := os.UserHomeDir()
	key := filepath.Join(home, ".ssh", "id_ed25519")
	os.WriteFile(key, nil, 0o600)                                  // 6: bad
	os.MkdirAll(filepath.Join(os.Getenv("HOME"), ".aws"), 0o700)   // 7: bad
	os.WriteFile(testhome.Path(t, key), nil, 0o600)                // fine
	safe := testhome.Path(t, filepath.Join(home, ".kube", "config"))
	os.WriteFile(safe, nil, 0o600)                                 // fine
	os.WriteFile(filepath.Join(t.TempDir(), "x"), nil, 0o600)      // fine
	os.Symlink("target", "~/link")                                 // 12: bad
	os.ReadFile(key)                                               // reading is not this test's business
	var conf = filepath.Join(testhome.Real(), "config.json")
	os.Remove(conf)                                                // 15: bad
}
func TestB(t *testing.T) {
	key := "elsewhere"
	os.WriteFile(key, nil, 0o600) // fine: another function's name
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x_test.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := homeWrites(fset, file)
	var lines []string
	for _, g := range got {
		lines = append(lines, strings.SplitN(g, ":", 2)[0])
	}
	if strings.Join(lines, ",") != "6,7,12,15" {
		t.Errorf("flagged lines %v, want 6, 7, 12, 15: %v", lines, got)
	}
}

// komando itself never contains this package: it is for tests only.
func TestNotInTheProgram(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../../cmd/komando").Output()
	if err != nil {
		t.Fatal("go list: ", err)
	}
	if strings.Contains(string(out), "internal/testhome") {
		t.Error("cmd/komando depends on internal/testhome")
	}
}
