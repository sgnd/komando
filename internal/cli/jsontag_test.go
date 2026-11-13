package cli

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// S-9.1, S-9.2: the JSON keys komando prints (internal/cli, internal/out)
// are snake_case, and a new key says what it holds in its name: a moment
// is <event>_at, a duration <what>_ms or <what>_seconds, a size
// <what>_bytes, a count <thing>_count, an exit status exit_code. Keys from
// before the rule (or of another program's API that komando reads) stay
// as they are: contract 1 never renames a key. They are listed in
// jsonTagAllowed (jsontag_list_test.go), which may only shrink. Rewrite it
// with KOMANDO_UPDATE_JSONTAGS=1 go test ./internal/cli -run TestJSONTagLint
// only to drop entries, never to add a new key that breaks the rule.
func TestJSONTagLint(t *testing.T) {
	snake := regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
	badSuffix := regexp.MustCompile(`(^|_)(time|date|duration|elapsed|secs|sec|size|len|num|exit|rc|exitcode)$`)
	got := map[string]string{}
	for _, dir := range []string{".", "../out"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			fs := token.NewFileSet()
			file, err := parser.ParseFile(fs, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			pkg := filepath.Base(filepath.Dir(f))
			if dir == "." {
				pkg = "cli"
			}
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				for _, fld := range st.Fields.List {
					if fld.Tag == nil {
						continue
					}
					tag := reflect.StructTag(strings.Trim(fld.Tag.Value, "`")).Get("json")
					name, _, _ := strings.Cut(tag, ",")
					if name == "" || name == "-" {
						continue
					}
					typ := exprString(fld.Type)
					var why string
					switch {
					case !snake.MatchString(name):
						why = "not snake_case"
					case strings.HasSuffix(typ, "time.Time") && !strings.HasSuffix(name, "_at"):
						why = "a moment is <event>_at"
					case strings.HasSuffix(typ, "time.Duration"):
						why = "a duration is <what>_ms or <what>_seconds, a number"
					case badSuffix.MatchString(name):
						why = "say the unit: _at, _ms, _seconds, _bytes, _count, exit_code"
					}
					if why != "" {
						got[pkg+"."+ts.Name.Name+"."+name] = why
					}
				}
				return true
			})
		}
	}
	if os.Getenv("KOMANDO_UPDATE_JSONTAGS") != "" {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString("package cli\n\n// jsonTagAllowed are the JSON keys from before S-9.1 and S-9.2 that break\n// them; contract 1 keeps them as they are (TestJSONTagLint). Only shrink it.\nvar jsonTagAllowed = []string{\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "\t%q, // %s\n", k, got[k])
		}
		b.WriteString("}\n")
		src, err := format.Source([]byte(b.String()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("jsontag_list_test.go", src, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	allowCheck(t, "S-9.1/S-9.2 (JSON key)", got, jsonTagAllowed)
}

func exprString(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprString(e.X) + "." + e.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(e.X)
	case *ast.ArrayType:
		return "[]" + exprString(e.Elt)
	case *ast.MapType:
		return "map[" + exprString(e.Key) + "]" + exprString(e.Value)
	}
	return ""
}
