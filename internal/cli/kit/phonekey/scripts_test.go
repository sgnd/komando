//go:build !windows

package phonekey

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// sh runs script as the server would: sh -c SCRIPT NAME ARGS...
func sh(t *testing.T, script string, args ...string) string {
	t.Helper()
	b, err := exec.Command("/bin/sh", append([]string{"-c", script, "komando-key"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return strings.TrimSpace(string(b))
}

// TestWriteScript: the line is added once, with a line break before it
// when the file lacks one; the same key in another line (an older line
// sshd would use first, also with a tab before the key) is reported and
// nothing is written; komando writes through no symlink.
func TestWriteScript(t *testing.T) {
	home := t.TempDir()
	k, err := Parse([]byte(pubLine(t, "ecdsa", "komando-phone-anna")))
	if err != nil {
		t.Fatal(err)
	}
	line, match := Line("/usr/local/bin/komando", k, "10.0.0.0/8"), k.Data
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("ssh-ed25519 AAAAold laptop"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sh(t, WriteScript, home, line, match); got != "added" {
		t.Fatalf("first: %s", got)
	}
	if got := sh(t, WriteScript, home, line, match); got != "present" {
		t.Errorf("again: %s", got)
	}
	b, _ := os.ReadFile(keys)
	if want := "ssh-ed25519 AAAAold laptop\n" + line + "\n"; string(b) != want {
		t.Errorf("file:\n%s\nwant:\n%s", b, want)
	}
	if got := sh(t, WriteScript, home, Line("/usr/local/bin/komando", k, ""), match); got != "other" {
		t.Errorf("another line for the key: %s", got)
	}
	if b2, _ := os.ReadFile(keys); string(b2) != string(b) {
		t.Errorf("written although the key had another line")
	}
	tabbed := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tabbed, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tabbed, ".ssh", "authorized_keys"), []byte(k.Type+"\t"+k.Data+"  old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sh(t, WriteScript, tabbed, line, match); got != "other" {
		t.Errorf("an older line with a tab before the key: %s", got)
	}
	other := t.TempDir()
	if err := os.Symlink(filepath.Join(other, "elsewhere"), filepath.Join(other, ".ssh")); err != nil {
		t.Fatal(err)
	}
	if got := sh(t, WriteScript, other, line, match); !strings.HasPrefix(got, "symlink ") {
		t.Errorf("through a symlink: %s", got)
	}
}

// TestProbeScript runs the probe for this test's own user on Linux: its
// uid by id, its home, and no komando.
func TestProbeScript(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the probe reads getent or /etc/passwd, which macOS keeps elsewhere")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "/usr/bin:/bin")
	f := ParseFacts(sh(t, ProbeScript, u.Username))
	if f.NoUser || f.UID != strconv.Itoa(os.Getuid()) || f.Home == "" {
		t.Errorf("%+v", f)
	}
}

// TestProbeRunsNoUserProgram: the probe asks komando for its server mode
// only when root alone could have changed it, since komando may log in as
// root. A komando the test user owns is never run. Mutant: running the
// --help check whatever the owner (safe=1 always) turns it red.
func TestProbeRunsNoUserProgram(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() == 0 {
		t.Skip("needs Linux (getent) and a user that is not root")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	fake := "#!/bin/sh\ntouch " + marker + "\n"
	if err := os.WriteFile(filepath.Join(bin, "komando"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	f := ParseFacts(sh(t, ProbeScript, u.Username))
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("the probe ran a komando the user owns")
	}
	if f.Gate || f.Komando == "" {
		t.Errorf("%+v", f)
	}
}
