package out

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// komando's own words reach AI agents through the masker. A hint that
// names the next command ("save its password: `komando secret set
// web1-pass`") must arrive whole: an agent that reads "[hidden] secret set
// web1-pass`" cannot follow it. Every Go string that names a komando
// command, and the playbook and skill agents read, must come out of
// MaskSecrets unchanged.
func TestMaskKeepsKomandoHints(t *testing.T) {
	checked := 0
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "testdata" {
			return filepath.SkipDir
		}
		switch {
		case d.IsDir():
			return nil
		case strings.HasSuffix(path, "_test.go"):
			return nil
		case strings.HasSuffix(path, ".go"):
			for _, s := range stringLiterals(t, path) {
				if strings.Contains(s, "`komando ") {
					checked++
					if got := MaskSecrets(s); got != s {
						t.Errorf("%s: the masker changes a hint:\n  %q\n→ %q", path, s, got)
					}
				}
			}
		case filepath.Base(path) == "guide.md" || filepath.Base(path) == "skill.md":
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			checked++
			for i, line := range strings.Split(string(b), "\n") {
				if got := MaskSecrets(line); got != line {
					t.Errorf("%s:%d: the masker changes what agents read:\n  %q\n→ %q", path, i+1, line, got)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 100 {
		t.Fatalf("only %d texts checked: is the walk looking at internal/?", checked)
	}
}

// Plain messages with words that look like secret names come out whole.
func TestMaskKeepsPlainMessages(t *testing.T) {
	for _, s := range []string{
		"the vault is locked with a passphrase; set KOMANDO_VAULT_PASS",
		"vault.key is missing but the vault holds 3 secrets; restore it from a backup",
		"secret-tool is not installed in /usr/bin (install it with apt install libsecret-tools)",
		"the registry ca option takes a secret reference, as in ?ca=secret:NAME",
		"the credential helper docker-credential-osxkeychain failed (exit status 1)",
		"the WireGuard private key does not parse (illegal base64 data at input byte 4)",
		"komando exec web1 --host-key-policy=strict -- uptime",
		"store its passphrase: `komando secret set deploy-pass`",
	} {
		if got := MaskSecrets(s); got != s {
			t.Errorf("masked:\n  %q\n→ %q", s, got)
		}
	}
	// the exemptions stay narrow: a real value after the same words is hidden
	for _, s := range []string{"password: hunter2", "password: `hunter2", "--db-password=hunter2", "private_key: abc123"} {
		if got := MaskSecrets(s); !strings.Contains(got, Hidden) {
			t.Errorf("not masked: %q → %q", s, got)
		}
	}
}

func stringLiterals(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				out = append(out, s)
			}
		}
		return true
	})
	return out
}
