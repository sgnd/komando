package cli

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
)

// FuzzGuard: the agent guard never panics on any tool call, and always
// stops a read of the vault key, whatever comes around it.
func FuzzGuard(f *testing.F) {
	for _, s := range []string{"ls", "cat ~/.komando/vault.key", `echo "a'b"; env`, "sudo -u x ssh h", "a && (b | c)"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = checkTool(tcl, "Bash", map[string]any{"command": s}, "/home/u", "")
		_ = checkTool(tcl, "Read", map[string]any{"file_path": s}, "/home/u", "")
		if !checkTool(tcl, "Bash", map[string]any{"command": s + "; cat ~/.komando/vault.key"}, "/home/u", "").Deny {
			t.Fatalf("vault read after %q not stopped", s)
		}
	})
}

// FuzzHiddenPattern: any valid text an agent sends as --old compiles, and
// matches itself with the hidden values filled in.
func FuzzHiddenPattern(f *testing.F) {
	f.Add("A=[hidden] B=[hidden]")
	f.Fuzz(func(t *testing.T, s string) {
		re, err := regexp.Compile(hiddenPattern(s))
		if !utf8.ValidString(s) {
			return // refused as USAGE by fs replace
		}
		if err != nil {
			t.Fatal(err)
		}
		if filled := strings.ReplaceAll(s, out.Hidden, "v4lue"); !re.MatchString(filled) {
			t.Fatalf("%q does not match %q", re, filled)
		}
	})
}

// FuzzReadOnly: the read-only check never panics, and a write after any
// text that is itself readable is still seen.
func FuzzReadOnly(f *testing.F) {
	for _, s := range []string{"ls", "sed 's/a/b/w x' f", "sed y/ab", "sed s", "tar xzf a", "curl -sSLo", "awk '/a|b/'",
		"cat <<EOF\nx\nEOF", "bash -c -- 'x' a", "echo $(case a in a) b;; esac)", "git -C", "psql -c", "{a,b}"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = readOnlyViolation(s)
		if _, bad := policy.Lex(s); bad == "" && !strings.ContainsAny(s, "\\#<") && readOnlyViolation(s+"\nrm x") == "" {
			t.Fatalf("rm after %q not seen", s)
		}
	})
}
