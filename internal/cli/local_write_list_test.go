package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// localWriters are the calls that put a file on this computer.
var localWriters = map[string]bool{
	"os.Create": true, "os.OpenFile": true, "os.WriteFile": true, "os.CreateTemp": true,
	"os.Rename": true, "os.Link": true, "store.WriteFileAtomic": true,
}

// checkedWriters write only after guardLocalWrite: calling one counts as
// the check.
var checkedWriters = map[string]bool{"guardLocalWrite": true, "writeAtomic": true, "writeReplacing": true, "fetchFile": true, "writeExport": true}

// writesOwnFiles are the functions that write on this computer without
// guardLocalWrite, and why that is right: none of them writes where a
// command's argument points.
var writesOwnFiles = map[string]string{
	"placeNew":          "fetchFile's last step, after its guardLocalWrite",
	"saveBackup":        "a free name next to an agent settings or skill file (guide install)",
	"installSkill":      "the skill in ~/.claude/skills or ~/.agents/skills, or in the project (noLinksUnder)",
	"installAgentHook":  "an agent harness's settings file (guide install)",
	"installGuardHook":  "Claude Code's settings file (guide install)",
	"removeGuard":       "an agent harness's settings file (guide uninstall)",
	"toolWithCA":        "a CA file in a new temporary folder of its own",
	"agentKeys":         "public key files in a new temporary folder of its own",
	"startHolder":       "a login's log file in komando's folder",
	"tunnelStartCmd":    "a tunnel's log file in komando's folder",
	"background":        "a VPN session's log file in komando's folder",
	"startSession":      "a VPN session's log file in komando's folder",
	"signInWindow.show": "a sign-in page in a new temporary folder of its own",
	"renameTx":          "moves key files inside komando's folder",
	"renameVpn":         "moves a VPN's folder inside komando's folder",
	"swapExe":           "komando's own program (update)",
	"replaceSelf":       "komando's own program (update)",
	"checkWritable":     "a test file next to komando's own program (update)",
}

// Every function in this package that writes a file on this computer goes
// through guardLocalWrite (directly or through a writer that does), or is
// listed in writesOwnFiles with the reason: a new command that saves a
// file cannot skip the check.
func TestEveryLocalWriterIsGuarded(t *testing.T) {
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	var missing []string
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				name = typeName(fd.Recv.List[0].Type) + "." + name
			}
			writes, checked := false, false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := c.Fun.(type) {
				case *ast.SelectorExpr:
					if x, ok := fn.X.(*ast.Ident); ok && localWriters[x.Name+"."+fn.Sel.Name] {
						writes = true
					}
				case *ast.Ident:
					if checkedWriters[fn.Name] {
						checked = true
					}
				}
				return true
			})
			if !writes || checked {
				continue
			}
			seen[name] = true
			if writesOwnFiles[name] == "" {
				missing = append(missing, f+": "+name)
			}
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s writes a file on this computer without guardLocalWrite: check its destination, or list it in writesOwnFiles with the reason", m)
	}
	for name := range writesOwnFiles {
		if !seen[name] {
			t.Errorf("writesOwnFiles lists %s, which no longer writes a file unchecked: drop it", name)
		}
	}
}

func typeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return typeName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return typeName(x.X)
	}
	return "?"
}
