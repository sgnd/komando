package interactive

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/sgnd/komando/"

// allowedImports is all the interactive mode may import besides the
// standard library (design note section 3.1): the capability table, the
// terminal and the output rules. Nothing that runs a command, writes the
// store or reads a secret.
var allowedImports = map[string]bool{
	module + "internal/capability":   true,
	module + "internal/cli/kit/term": true,
	module + "internal/out":          true,
}

// bannedImports and bannedCalls would give the screen a second way to run
// something: it returns argv and nothing else.
var bannedImports = map[string]bool{"os/exec": true, "syscall": true, "plugin": true, "unsafe": true}

var bannedCalls = map[string]bool{"os.Exit": true, "os.StartProcess": true}

// The interactive mode imports only what section 3.1 allows and never
// ends the process or starts one. go/parser over the package's own files:
// the same view a reviewer has, with no build step.
func TestInteractiveImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		problems, err := importProblems(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range problems {
			t.Errorf("%s: %s", f, p)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no program files found to check")
	}
}

// The check itself fails on each kind of thing it forbids.
func TestInteractiveImportsCatches(t *testing.T) {
	src := `package interactive

import (
	"os"
	"os/exec"
	"github.com/sgnd/komando/internal/cli"
	"github.com/sgnd/komando/internal/store"
	"golang.org/x/term"
)

func f() { _ = exec.Command("x"); os.Exit(1); os.StartProcess("x", nil, nil) }
`
	p := filepath.Join(t.TempDir(), "bad.go")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	problems, err := importProblems(p)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(problems, "\n")
	for _, want := range []string{`"os/exec"`, `"` + module + `internal/cli"`, `"` + module + `internal/store"`, `"golang.org/x/term"`, "os.Exit", "os.StartProcess"} {
		if !strings.Contains(got, want) {
			t.Errorf("the check did not name %s; it said:\n%s", want, got)
		}
	}
}

// importProblems lists what file imports or calls that the interactive
// mode may not.
func importProblems(file string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, im := range f.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		std := !strings.Contains(strings.SplitN(path, "/", 2)[0], ".")
		switch {
		case bannedImports[path]:
			problems = append(problems, "imports "+im.Path.Value+": the screen starts nothing")
		case std, allowedImports[path]:
		default:
			problems = append(problems, "imports "+im.Path.Value+": only internal/capability, internal/cli/kit/term, internal/out and the standard library")
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok {
			if x, ok := s.X.(*ast.Ident); ok && bannedCalls[x.Name+"."+s.Sel.Name] {
				problems = append(problems, "calls "+x.Name+"."+s.Sel.Name+": the screen returns argv and ends nothing")
			}
		}
		return true
	})
	return problems, nil
}
