package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Every remote command komando runs keeps a bounded part of its output: a
// server that floods stdout must not fill this computer's memory (reboot's
// commands had no bound). A sshx.RunRequest literal sets MaxOutput, unless
// it only builds the command line (sshx.BuildCommand runs nothing).
func TestEveryRunRequestBoundsOutput(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		builds := map[ast.Expr]bool{}
		ast.Inspect(af, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "BuildCommand" {
					for _, a := range call.Args {
						builds[a] = true
					}
				}
			}
			return true
		})
		ast.Inspect(af, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || builds[lit] {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "RunRequest" {
				return true
			}
			for _, el := range lit.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "MaxOutput" {
						return true
					}
				}
			}
			t.Errorf("%s: a sshx.RunRequest without MaxOutput", fset.Position(lit.Pos()))
			return true
		})
	}
}
