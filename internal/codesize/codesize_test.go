// Package codesize keeps komando's code in pieces a person (or an agent)
// can read in one go: no function over maxFuncLines, no file over
// maxFileLines. Code that was already bigger when the rule came is listed
// in testdata/allowed.txt with its size then; it may shrink, never grow,
// and its line goes once it fits. To refresh the list after making
// something smaller:
//
//	go test ./internal/codesize -update
package codesize

import (
	"bufio"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	maxFuncLines = 100
	maxFileLines = 800
	allowedFile  = "testdata/allowed.txt"
)

var update = flag.Bool("update", false, "rewrite testdata/allowed.txt from the code as it is now")

// measure returns the size of every file and function over the limits, as
// "file PATH" / "func PATH NAME" keys with their line counts. Tests and
// test helpers are left out: only the program counts.
func measure(t *testing.T) map[string]int {
	t.Helper()
	root := filepath.Join("..", "..")
	big := map[string]int{}
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			if n := fset.File(f.Pos()).LineCount(); n > maxFileLines {
				big["file "+rel] = n
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				n := fset.Position(fn.End()).Line - fset.Position(fn.Pos()).Line + 1
				if n > maxFuncLines {
					big["func "+rel+" "+funcName(fn)] = n
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return big
}

// funcName is NAME, or TYPE.NAME for a method.
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	typ := fn.Recv.List[0].Type
	if s, ok := typ.(*ast.StarExpr); ok {
		typ = s.X
	}
	if g, ok := typ.(*ast.IndexExpr); ok { // generic receiver T[X]
		typ = g.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

func readAllowed(t *testing.T) map[string]int {
	t.Helper()
	f, err := os.Open(allowedFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	allowed := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		n, err := strconv.Atoi(line[i+1:])
		if i < 0 || err != nil {
			t.Fatalf("%s: bad line %q (want KEY LINES)", allowedFile, line)
		}
		allowed[line[:i]] = n
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return allowed
}

func writeAllowed(t *testing.T, big map[string]int) {
	t.Helper()
	keys := make([]string, 0, len(big))
	for k := range big {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "# Code that was over the size limits (functions %d lines, files %d)\n", maxFuncLines, maxFileLines)
	b.WriteString("# when the rule came. Each may shrink, never grow; see codesize_test.go.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s %d\n", k, big[k])
	}
	if err := os.WriteFile(allowedFile, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCodeSize(t *testing.T) {
	big := measure(t)
	if *update {
		writeAllowed(t, big)
		return
	}
	allowed := readAllowed(t)
	keys := make([]string, 0, len(big))
	for k := range big {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		n := big[k]
		was, ok := allowed[k]
		limit := maxFuncLines
		if strings.HasPrefix(k, "file ") {
			limit = maxFileLines
		}
		switch {
		case !ok:
			t.Errorf("%s: %d lines, the limit is %d: split it into smaller pieces", k, n, limit)
		case n > was:
			t.Errorf("%s: grew from %d to %d lines, over the limit of %d: split it instead of adding to it", k, was, n, limit)
		}
	}
	for k := range allowed {
		if _, ok := big[k]; !ok {
			t.Errorf("%s fits the limit now (or is gone): run `go test ./internal/codesize -update` to drop its line", k)
		}
	}
}
