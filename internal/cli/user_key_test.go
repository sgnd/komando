//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runUserKeyScript runs userKeyScript with stand-ins for getent, id, chown
// and su (suRuns: su runs its command as this user; else it does nothing).
func runUserKeyScript(t *testing.T, home string, suRuns bool) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "log")
	su := "#!/bin/sh\necho su >> \"$LOG\"\n"
	if suRuns {
		su += "shift 4\nexec /bin/sh -c \"$@\"\n"
	}
	for name, body := range map[string]string{
		"getent": "#!/bin/sh\necho \"bob:x:1:1::$FAKEHOME:/bin/sh\"\n",
		"id":     "#!/bin/sh\necho staff\n",
		"chown":  "#!/bin/sh\necho \"chown $*\" >> \"$LOG\"\n",
		"su":     su,
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	c := exec.Command("/bin/sh", "-c", userKeyScript("bob", "ssh-ed25519 AAAAkey bob@x"))
	c.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "LOG=" + log, "FAKEHOME=" + home}
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	b, _ := os.ReadFile(log)
	return string(b)
}

// The user's links at ~/.ssh get nothing from root: no file is made or
// written through them, and no chown follows them.
func TestUserKeyScriptFollowsNoLink(t *testing.T) {
	home, elsewhere := t.TempDir(), t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	log := runUserKeyScript(t, home, false)
	if ents, _ := os.ReadDir(elsewhere); len(ents) > 0 {
		t.Fatalf("root wrote through the user's link: %v", ents)
	}
	for _, l := range strings.Split(strings.TrimSpace(log), "\n") {
		if strings.HasPrefix(l, "chown ") && !strings.HasPrefix(l, "chown -h ") {
			t.Fatalf("a chown that follows links: %q", l)
		}
	}
}

// As the user, the key goes in once, with private modes.
func TestUserKeyScriptAddsKeyOnce(t *testing.T) {
	home := t.TempDir()
	runUserKeyScript(t, home, true)
	runUserKeyScript(t, home, true)
	f := filepath.Join(home, ".ssh", "authorized_keys")
	b, err := os.ReadFile(f)
	if err != nil || strings.Count(string(b), "AAAAkey") != 1 {
		t.Fatalf("authorized_keys %q %v", b, err)
	}
	if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Dir(f)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode())
	}
}
