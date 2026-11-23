// Package postquantum keeps komando's key exchange post-quantum hybrid
// first: SSH offers mlkem768x25519-sha256 first and no code narrows the
// list; a TLS config names X25519MLKEM768 when it sets curves and never caps
// the version below TLS 1.3. classicalOnly lists the files allowed to break
// the TLS rules, each with its reason; an entry whose file no longer sets
// such a field fails, so the list only shrinks.
package postquantum

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

var classicalOnly = map[string]string{
	"internal/cli/cert_tls.go": "cert check reads a certificate from servers and middleboxes that drop the large hybrid hello; it leaves the CLI with cert",
}

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
			t.Errorf("%s: sets KeyExchanges without %s first", set.where(), ssh.KeyExchangeMLKEM768X25519)
		}
	}
}

func TestCurvePreferencesHybrid(t *testing.T) {
	seen := map[string]bool{}
	for _, set := range fieldSets(t, "CurvePreferences") {
		seen[set.file] = true
		if _, ok := classicalOnly[set.file]; !ok && !namesHybrid(set.value) {
			t.Errorf("%s: sets CurvePreferences without tls.X25519MLKEM768", set.where())
		}
	}
	for _, set := range fieldSets(t, "MaxVersion") {
		seen[set.file] = true
		if _, ok := classicalOnly[set.file]; !ok && !isSelector(set.value, "VersionTLS13") {
			t.Errorf("%s: caps the TLS version below 1.3, which has no hybrid key exchange", set.where())
		}
	}
	for file := range classicalOnly {
		if !seen[file] {
			t.Errorf("%s: listed as classical only, but it sets no CurvePreferences or MaxVersion (or is gone): drop it from the list", file)
		}
	}
}

func TestFieldSetsSeesBothForms(t *testing.T) {
	src := `package p
var a = T{KeyExchanges: []string{"x"}}
func f(c *T) { c.KeyExchanges = nil }`
	got := setsIn(t, "p.go", src, "KeyExchanges")
	if len(got) != 2 {
		t.Fatalf("found %d sets, want the literal and the assignment", len(got))
	}
}

func isHybridKex(e ast.Expr) bool {
	if isSelector(e, "KeyExchangeMLKEM768X25519") {
		return true
	}
	b, ok := e.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(b.Value)
	return err == nil && s == ssh.KeyExchangeMLKEM768X25519
}

func namesHybrid(e ast.Expr) bool {
	lit, ok := e.(*ast.CompositeLit)
	return ok && slices.ContainsFunc(lit.Elts, func(el ast.Expr) bool { return isSelector(el, "X25519MLKEM768") })
}

func isSelector(e ast.Expr, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == name
}

// fieldSet is one place program code gives a struct field a value.
type fieldSet struct {
	file  string // slash path from the module root
	pos   token.Position
	value ast.Expr
}

func (s fieldSet) where() string { return s.file + ":" + strconv.Itoa(s.pos.Line) }

// fieldSets finds every `Field: value` and `x.Field = value` in the
// program files of internal/ and cmd/ (tests left out).
func fieldSets(t *testing.T, field string) []fieldSet {
	t.Helper()
	root := filepath.Join("..", "..")
	var sets []fieldSet
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			sets = append(sets, setsIn(t, filepath.ToSlash(rel), string(src), field)...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return sets
}

func setsIn(t *testing.T, file, src, field string) []fieldSet {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var sets []fieldSet
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.KeyValueExpr:
			if id, ok := n.Key.(*ast.Ident); ok && id.Name == field {
				sets = append(sets, fieldSet{file, fset.Position(n.Pos()), n.Value})
			}
		case *ast.AssignStmt:
			for i, l := range n.Lhs {
				if isSelector(l, field) && i < len(n.Rhs) {
					sets = append(sets, fieldSet{file, fset.Position(n.Pos()), n.Rhs[i]})
				}
			}
		}
		return true
	})
	return sets
}
