//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runRevokeScript(t *testing.T, home string, suRuns bool) string {
	t.Helper()
	bin := t.TempDir()
	su := "#!/bin/sh\n"
	if suRuns {
		su += "shift 4\nexec /bin/sh -c \"$@\"\n"
	}
	for name, body := range map[string]string{
		"getent": "#!/bin/sh\necho \"bob:x:1:1::$FAKEHOME:/bin/sh\"\n",
		"id":     "#!/bin/sh\necho root\n",
		"su":     su,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	c := exec.Command("/bin/sh", "-c", revokeScript("bob", "AAAAold", false))
	c.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "FAKEHOME=" + home}
	b, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return strings.TrimSpace(string(b))
}

// As root for --user, nothing is read or written in the user's .ssh: a link
// they planted there (at authorized_keys or a temporary name) gets nothing.
func TestRevokeScriptRootTouchesNoUserFile(t *testing.T) {
	home := t.TempDir()
	victim := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(victim, []byte("root ALL\nAAAAold\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	if err := os.Symlink(victim, filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	runRevokeScript(t, home, false)
	if b, _ := os.ReadFile(victim); string(b) != "root ALL\nAAAAold\n" {
		t.Fatalf("root changed the file behind the link: %q", b)
	}
}

// As the user, the key's lines go and the rest stays.
func TestRevokeScriptRemovesKey(t *testing.T) {
	home := t.TempDir()
	f := filepath.Join(home, ".ssh", "authorized_keys")
	_ = os.MkdirAll(filepath.Dir(f), 0o700)
	if err := os.WriteFile(f, []byte("ssh-ed25519 AAAAold a\nssh-ed25519 AAAAkeep b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := runRevokeScript(t, home, true); n != "1" {
		t.Fatalf("count %q", n)
	}
	if b, _ := os.ReadFile(f); string(b) != "ssh-ed25519 AAAAkeep b\n" {
		t.Fatalf("file %q", b)
	}
	if ents, _ := os.ReadDir(filepath.Dir(f)); len(ents) != 1 {
		t.Fatalf("left over: %v", ents)
	}
}
