package interactive

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/sgnd/komando/"

// allowedImports is all the interactive mode may import (design note
// section 3.1): a few standard packages for text and lists, the capability
// table, the terminal and the output rules. Nothing that runs a command,
// opens a file or a connection, writes the store or reads a secret.
var allowedImports = map[string]bool{
	"context": true, "errors": true, "fmt": true, "maps": true, "slices": true,
	"sort": true, "strings": true, "unicode": true, "unicode/utf8": true,
	module + "internal/capability":   true,
	module + "internal/cli/kit/term": true,
	module + "internal/out":          true,
}

// bannedCalls would end the process or start one, by import path and
// name: an alias of the package (import o "os") is caught too.
var bannedCalls = map[string]bool{"os.Exit": true, "os.StartProcess": true, "syscall.Exec": true, "syscall.ForkExec": true}

// bannedDeps must never be reached through any import, however deep:
// running a command, loading code, the store, the secrets, SSH, or the
// commands themselves. syscall and unsafe are not here: every package
// that uses os reaches them; they are refused as direct imports instead.
var bannedDeps = []string{"os/exec", "plugin", module + "internal/store", module + "internal/vault", module + "internal/sshx", module + "internal/cli"}

// The interactive mode and every package under it import only what
// section 3.1 allows and never end the process or start one. go/parser
// over the files themselves: the same view a reviewer has.
func TestInteractiveImports(t *testing.T) {
	problems, checked, err := boundaryProblems(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	if checked == 0 {
		t.Fatal("no program files found to check")
	}
}

// Nothing the interactive mode imports reaches a banned package, at any
// depth (go list -deps).
func TestInteractiveImportsTransitive(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool here to list the dependencies")
	}
	out, err := exec.Command(gobin, "list", "-deps", "./...").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Fields(string(out))
	if !slices.Contains(deps, module+"internal/interactive") {
		t.Fatalf("go list did not list the package itself: %q", deps)
	}
	if p := depProblems(deps); len(p) > 0 {
		t.Errorf("banned dependencies: %v", p)
	}
}

// The checks fail on each kind of thing they forbid: an import outside
// the allowlist, an aliased banned call, a file in a package below, and a
// banned package deep in the dependencies.
func TestInteractiveImportsCatches(t *testing.T) {
	root := t.TempDir()
	write := func(name, src string) {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("bad.go", `package interactive

import (
	o "os"
	"os/exec"
	"net/http"
	"github.com/sgnd/komando/internal/cli"
	"github.com/sgnd/komando/internal/store"
	"golang.org/x/term"
)

func f() { _ = exec.Command("x"); o.Exit(1); o.StartProcess("x", nil, nil) }
`)
	write("form/sub.go", "package form\n\nimport \"net\"\n")
	write("testdata/skipped.go", "package skipped\n\nimport \"net\"\n")
	write("ok_test.go", "package interactive\n\nimport \"net\"\n")
	problems, _, err := boundaryProblems(root)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(problems, "\n")
	for _, want := range []string{
		`bad.go: imports "os"`, `bad.go: imports "os/exec"`, `bad.go: imports "net/http"`,
		`"` + module + `internal/cli"`, `"` + module + `internal/store"`, `"golang.org/x/term"`,
		"calls os.Exit", "calls os.StartProcess",
		filepath.Join("form", "sub.go") + `: imports "net"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the check did not name %s; it said:\n%s", want, got)
		}
	}
	for _, skipped := range []string{"testdata", "ok_test.go"} {
		if strings.Contains(got, skipped) {
			t.Errorf("the check read %s, which is not program code:\n%s", skipped, got)
		}
	}
	deep := depProblems([]string{"fmt", "os", "syscall", "os/exec", module + "internal/cli", module + "internal/cli/kit/term", module + "internal/vault"})
	if want := []string{"os/exec", module + "internal/cli", module + "internal/vault"}; !slices.Equal(deep, want) {
		t.Errorf("deep dependencies flagged %v, want %v", deep, want)
	}
}

// boundaryProblems checks every program file under root (tests and
// testdata are not program code), and says how many it read.
func boundaryProblems(root string) (problems []string, checked int, err error) {
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && d.Name() == "testdata":
			return filepath.SkipDir
		case d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go"):
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		found, err := importProblems(p)
		for _, f := range found {
			problems = append(problems, rel+": "+f)
		}
		checked++
		return err
	})
	return problems, checked, err
}

// importProblems lists what file imports or calls that the interactive
// mode may not.
func importProblems(file string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var problems []string
	names := map[string]string{} // the name a file uses for an import, to its path
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := path.Base(p)
		if im.Name != nil {
			name = im.Name.Name
		}
		names[name] = p
		if !allowedImports[p] {
			problems = append(problems, "imports "+im.Path.Value+": only "+allowedList())
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok {
			if x, ok := s.X.(*ast.Ident); ok && bannedCalls[names[x.Name]+"."+s.Sel.Name] {
				problems = append(problems, "calls "+names[x.Name]+"."+s.Sel.Name+": the screen returns answers and ends nothing")
			}
		}
		return true
	})
	return problems, nil
}

// depProblems is the banned packages among deps.
func depProblems(deps []string) []string {
	var found []string
	for _, d := range deps {
		if slices.Contains(bannedDeps, d) {
			found = append(found, d)
		}
	}
	return found
}

func allowedList() string {
	var l []string
	for p := range allowedImports {
		l = append(l, strings.TrimPrefix(p, module))
	}
	slices.Sort(l)
	return strings.Join(l, ", ")
}
