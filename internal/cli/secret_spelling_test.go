package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Owner O-09: references are spelled credential:NAME everywhere, and no
// code reads or writes the old secret:NAME spelling, apart from the one
// place that moves old stores (the format-3 migration), the F10 check
// that refuses a leftover and HasHidden's refusal of v0.17's [secret:NAME]
// label. A string literal that holds "secret:" anywhere else is a reader,
// a builder or a help text of the old spelling.
func TestNoSecretSpellingLeft(t *testing.T) {
	allowed := func(path string) bool {
		base := filepath.Base(path)
		return strings.HasPrefix(base, "migrate3") && filepath.Base(filepath.Dir(path)) == "store"
	}
	refusal := func(path, s string) bool {
		return filepath.ToSlash(path) == "../../internal/out/mask.go" && s == `\[secret:[A-Za-z0-9_.@/-]+\]`
	}
	root := filepath.Join("..", "..")
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || d.Name() == ".git" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || allowed(path) {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if s, err := strconv.Unquote(lit.Value); err == nil && strings.Contains(s, "secret:") && !refusal(path, s) {
				found = append(found, fset.Position(lit.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Errorf("%d string literals still spell secret: (first: %s)", len(found), strings.Join(found[:min(5, len(found))], ", "))
	}
}
