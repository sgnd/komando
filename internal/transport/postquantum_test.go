package transport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TLS key exchange is post-quantum hybrid first: Go offers X25519MLKEM768
// by default, so a TLS config that sets CurvePreferences must name it.
// classicalOnly are the files allowed to leave it out, each with its
// reason; an entry whose file is gone fails, so the list only shrinks.
var classicalOnly = map[string]string{
	"internal/cli/cert_tls.go": "cert check reads a certificate from servers and middleboxes that drop the large hybrid hello; it leaves the CLI with cert",
}

func TestCurvePreferencesHybrid(t *testing.T) {
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join("..", "..", dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(filepath.Join("..", ".."), p)
			rel = filepath.ToSlash(rel)
			ast.Inspect(f, func(n ast.Node) bool {
				kv, ok := n.(*ast.KeyValueExpr)
				if id, isID := keyIdent(kv, ok); !isID || id != "CurvePreferences" {
					return true
				}
				seen[rel] = true
				if _, allowed := classicalOnly[rel]; !allowed && !namesHybrid(kv.Value) {
					t.Errorf("%s: sets CurvePreferences without tls.X25519MLKEM768", fset.Position(kv.Pos()))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for file := range classicalOnly {
		if !seen[file] {
			t.Errorf("%s: listed as classical only, but it sets no CurvePreferences (or is gone): drop it from the list", file)
		}
	}
}

func keyIdent(kv *ast.KeyValueExpr, ok bool) (string, bool) {
	if !ok {
		return "", false
	}
	id, isID := kv.Key.(*ast.Ident)
	if !isID {
		return "", false
	}
	return id.Name, true
}

func namesHybrid(e ast.Expr) bool {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	return slices.ContainsFunc(lit.Elts, func(el ast.Expr) bool {
		sel, ok := el.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "X25519MLKEM768"
	})
}
