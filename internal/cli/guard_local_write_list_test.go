package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// localWriters are the calls that put a file on this computer.
var localWriters = map[string]bool{
	"os.Create": true, "os.OpenFile": true, "os.WriteFile": true, "os.CreateTemp": true,
	"os.Rename": true, "os.Link": true, "store.WriteFileAtomic": true,
	"os.Mkdir": true, "os.MkdirAll": true, "os.MkdirTemp": true, "os.Symlink": true, "os.Remove": true, "os.RemoveAll": true,
	"os.Chmod": true, "os.Chtimes": true, "os.Truncate": true,
}

// checkedWriters write only after guardLocalWrite: calling one counts as
// the check.
var checkedWriters = map[string]bool{"guardLocalWrite": true, "guardDownload": true, "mkdirLocal": true, "writeAtomic": true, "writeReplacing": true, "fetchFile": true, "writeExport": true}

// writesOwnFiles are the functions that write on this computer without
// guardLocalWrite, and why that is right: none of them writes where a
// command's argument points.
var writesOwnFiles = map[string]string{
	"placeNew":          "fetchFile's last step, after its guardLocalWrite",
	"ticketLine":        "a spawn ticket in komando's own spawn folder, named by komando",
	"checkTicket":       "removes that ticket once it is used",
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
	"toolCA.remove":     "removes its own temporary CA folder",
	"removeSkill":       "the skill guide install wrote (--project: noLinksUnder first)",
	"sealedSSHFiles":    "key copies in a new temporary folder of its own",
	"endLogin":          "a login's socket and files in komando's folder",
	"heldSocket":        "a login's socket in komando's folder or a random temporary name",
	"loginHolderCmd":    "a login's socket and files in komando's folder",
	"sweepLogs":         "old log files in komando's folder",
	"tunnelWait":        "a tunnel's files in komando's folder",
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
			// the check must come before the first write (a folder made
			// before the check is a write too)
			firstWrite, firstCheck := token.NoPos, token.NoPos
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := c.Fun.(type) {
				case *ast.SelectorExpr:
					if x, ok := fn.X.(*ast.Ident); ok && localWriters[x.Name+"."+fn.Sel.Name] && (firstWrite == token.NoPos || c.Pos() < firstWrite) {
						firstWrite = c.Pos()
					}
				case *ast.Ident:
					if checkedWriters[fn.Name] && (firstCheck == token.NoPos || c.Pos() < firstCheck) {
						firstCheck = c.Pos()
					}
				}
				return true
			})
			if firstWrite == token.NoPos || firstCheck != token.NoPos && firstCheck < firstWrite {
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

// otherPackageWriters are the functions outside this package that write
// on this computer, and why none needs guardLocalWrite: none writes where
// an agent's argument points. A new one fails TestOtherPackagesWriteOwnFiles
// until it is listed here (or its callers check its destination).
var otherPackageWriters = map[string]string{
	"browserx.Open":             "a sign-in browser profile in a new temporary folder",
	"browserx.Close":            "removes that profile",
	"cloud.writeTokenFile":      "the AWS SSO token cache, `login aws`",
	"cloud.AWSSSOLogout":        "removes that cache, `logout aws`",
	"cloud.bwDeviceID":          "Bitwarden's device id in komando's folder",
	"netx.Lock":                 "a VPN lock file in komando's folder",
	"netx.ForgetTailscale":      "a Tailscale VPN's state in komando's folder",
	"sealdb.openFile":           "komando's sealed store",
	"sealdb.Backup":             "a copy of the sealed store in komando's folder",
	"sealdb.syncFile":           "komando's sealed store",
	"sshx.WritePinsFile":        "a known_hosts copy in a new temporary folder (host ssh-command)",
	"store.createDB":            "komando's folder",
	"store.writeNewStore":       "komando's folder",
	"store.Rekey":               "komando's folder",
	"store.CheckWritable":       "a test file in komando's folder",
	"store.AcceptOldCopy":       "komando's folder",
	"store.MkdirPrivate":        "folders in komando's folder",
	"store.tightenHome":         "komando's folder",
	"store.ensureHome":          "komando's folder",
	"store.Lock":                "a lock file in komando's folder",
	"store.WriteFileAtomic":     "writes where its caller says; the callers here are checked by TestEveryLocalWriterIsGuarded",
	"tmpclean.RemoveAll":        "komando's own temporary files",
	"tmpclean.Sweep":            "komando's own temporary files of earlier runs",
	"vault.removeOldStoreKey":   "the store key in komando's folder",
	"vault.writeNewKeyFile":     "the store key in komando's folder",
	"vault.settleNewKeyFile":    "the store key in komando's folder",
	"vault.sealedKeyToKeychain": "the store key in komando's folder",
	"vault.newKeyFile":          "the store key in komando's folder",
}

func TestOtherPackagesWriteOwnFiles(t *testing.T) {
	fset := token.NewFileSet()
	var files []string
	filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && (filepath.ToSlash(p) == "../cli" || d.Name() == "e2e" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if err == nil && strings.HasSuffix(p, ".go") {
			files = append(files, p)
		}
		return nil
	})
	seen := map[string]bool{}
	{
		for _, f := range files {
			pkg := filepath.Base(filepath.Dir(f))
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
				writes := false
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						if s, ok := c.Fun.(*ast.SelectorExpr); ok {
							if x, ok := s.X.(*ast.Ident); ok && x.Name == "os" && localWriters["os."+s.Sel.Name] {
								writes = true
							}
						}
					}
					return true
				})
				if !writes {
					continue
				}
				name := pkg + "." + fd.Name.Name
				seen[name] = true
				if otherPackageWriters[name] == "" {
					t.Errorf("%s (%s) writes on this computer: list it in otherPackageWriters with the reason, or have its callers use guardLocalWrite", name, f)
				}
			}
		}
	}
	for name := range otherPackageWriters {
		if !seen[name] {
			t.Errorf("otherPackageWriters lists %s, which no longer writes: drop it", name)
		}
	}
}
