package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// kitFiles are the 57 program files that become the one package kit: the
// call, argument and platform files (16), the guard, read-only and risk
// files (21), the approval, confirm and ask files (19) and login_ask.go.
// They are listed by name so that a move of exactly these files changes
// nothing here but the directory the test reads.
var kitFiles = []string{
	"approval.go", "approval_body.go", "approval_code.go", "approval_debug.go", "approval_encoded.go",
	"approval_hint.go", "approval_lang.go", "approval_lang_other.go", "approval_lang_windows.go",
	"approval_trust.go", "approval_view.go", "approval_win_other.go", "approval_win_windows.go",
	"approval_words.go", "approval_words_id.go", "args_passthrough.go", "args_words.go",
	"ask_password.go", "ask_ssh.go", "call.go", "call_hooks.go", "common.go", "confirm_tty.go",
	"confirm_typed.go", "guard.go", "guard_agents.go", "guard_before_lock.go", "guard_delete.go",
	"guard_home.go", "guard_hook.go", "guard_local_write.go", "guard_path.go", "guard_protected.go", "guard_readers.go",
	"guard_shell.go", "guard_spawn.go", "localtool.go", "localtool_unix.go", "localtool_windows.go",
	"login_ask.go", "personal.go", "personal_guard.go", "platform_nopeek_linux.go",
	"platform_nopeek_other.go", "platform_unix.go", "platform_windows.go", "readonly.go",
	"readonly_forms.go", "readonly_kill.go", "readonly_tools.go", "readonly_words.go",
	"readonly_wrappers.go", "risk.go", "risk_keys.go", "sensitive.go", "stdin.go", "via.go",
}

// kitExports is every name those files export: the functions, types,
// variables and constants, and the exported methods as Type.Method. A new
// export fails here until it is reviewed; the test seams, guardWith and
// clickForgeable stay unexported.
var kitExports = []string{
	"Execute", "Guard", "GuardConns", "GuardScript", "RunCall",
	"eofReader.Read", "keepWriter.Write", "tier.String",
}

func TestKitExports(t *testing.T) {
	if len(kitFiles) != 57 {
		t.Fatalf("kitFiles lists %d files, want 57", len(kitFiles))
	}
	var got []string
	fset := token.NewFileSet()
	for _, f := range kitFiles {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv == nil {
					got = append(got, d.Name.Name)
				} else {
					got = append(got, recvName(d.Recv.List[0].Type)+"."+d.Name.Name)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							got = append(got, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								got = append(got, n.Name)
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(got)
	want := append([]string(nil), kitExports...)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("the kit files export %v, the reviewed list is %v: review the change, then update kitExports", got, want)
	}
}

// A program file whose name has a kit prefix is a kit file, so one added
// later must be added to kitFiles on purpose, after review.
func TestKitFilesAreComplete(t *testing.T) {
	in := map[string]bool{}
	for _, f := range kitFiles {
		in[f] = true
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []string{"call", "common", "args", "stdin", "platform", "localtool", "personal", "via",
		"guard", "readonly", "sensitive", "risk", "approval", "confirm", "ask"}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		base := strings.TrimSuffix(name, ".go")
		kit := base == "login_ask"
		for _, p := range prefixes {
			if base == p || strings.HasPrefix(base, p+"_") {
				kit = true
			}
		}
		if kit && !in[name] {
			t.Errorf("%s has a kit prefix and is not in kitFiles: review it, then add it", name)
		}
	}
	for f := range in {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("kitFiles names %s, which is not there", f)
		}
	}
}

// recvName is the type name of a method's receiver, without * or type
// arguments.
func recvName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return recvName(e.X)
	case *ast.IndexExpr:
		return recvName(e.X)
	case *ast.Ident:
		return e.Name
	}
	return "?"
}
