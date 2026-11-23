package sshx

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// SSH key exchange is post-quantum hybrid first: golang.org/x/crypto offers
// mlkem768x25519-sha256 first by default, and no komando code narrows the
// list. An update of the library that drops it, or a config that sets
// KeyExchanges without it in front, fails here.

func TestDefaultKeyExchangeIsHybrid(t *testing.T) {
	var c ssh.Config
	c.SetDefaults()
	if len(c.KeyExchanges) == 0 || c.KeyExchanges[0] != ssh.KeyExchangeMLKEM768X25519 {
		t.Errorf("default key exchanges start with %v, want %s first", c.KeyExchanges, ssh.KeyExchangeMLKEM768X25519)
	}
}

func TestNoCodeNarrowsKeyExchange(t *testing.T) {
	for _, set := range fieldSets(t, "KeyExchanges") {
		lit, ok := set.value.(*ast.CompositeLit)
		if !ok || len(lit.Elts) == 0 || !isHybridKex(lit.Elts[0]) {
			t.Errorf("%s: sets KeyExchanges without %s first", set.where, ssh.KeyExchangeMLKEM768X25519)
		}
	}
}

func isHybridKex(e ast.Expr) bool {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		return sel.Sel.Name == "KeyExchangeMLKEM768X25519"
	}
	if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
		s, err := strconv.Unquote(b.Value)
		return err == nil && s == ssh.KeyExchangeMLKEM768X25519
	}
	return false
}

// fieldSet is one place program code gives a struct field a value.
type fieldSet struct {
	where string
	value ast.Expr
}

// fieldSets finds every `Field: value` and `x.Field = value` in the
// program files of internal/ and cmd/ (tests left out).
func fieldSets(t *testing.T, field string) []fieldSet {
	t.Helper()
	var sets []fieldSet
	fset := token.NewFileSet()
	for _, dir := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.KeyValueExpr:
					if id, ok := n.Key.(*ast.Ident); ok && id.Name == field {
						sets = append(sets, fieldSet{fset.Position(n.Pos()).String(), n.Value})
					}
				case *ast.AssignStmt:
					for i, l := range n.Lhs {
						if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == field && i < len(n.Rhs) {
							sets = append(sets, fieldSet{fset.Position(n.Pos()).String(), n.Rhs[i]})
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return sets
}
