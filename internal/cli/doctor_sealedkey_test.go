package cli

import (
	"strings"
	"testing"
)

// doctor finds a key komando made in the store, where it lives, and says
// nothing about a missing file.
func TestDoctorSealedKey(t *testing.T) {
	invHome(t)
	mustRun(t, "credential", "key", "create", "deploy")
	d, _ := invRun(t, "doctor")
	for _, c := range d["inventory"].([]any) {
		m := c.(map[string]any)
		if m["name"] == "key:deploy" && m["ok"] != true {
			t.Fatalf("doctor fails a key in the store: %v", m)
		}
	}
}

// key gen --dry-run shows the place and the SSH type the real run gives
// the key, and makes no key (C08).
func TestKeyGenDryRunShowsPath(t *testing.T) {
	invHome(t)
	for _, c := range []struct {
		args []string
		typ  string
	}{
		{[]string{"credential", "key", "create", "k1", "--dry-run"}, "ssh-ed25519"},
		{[]string{"credential", "key", "create", "k2", "--type", "ecdsa", "-b", "384", "--dry-run"}, "ecdsa-sha2-nistp384"},
		{[]string{"credential", "key", "create", "k3", "--type", "rsa", "--dry-run"}, "ssh-rsa"},
	} {
		d := mustRun(t, c.args...)
		if d["path"] != "sealed:" || d["type"] != c.typ || d["action"] != "would_add" {
			t.Errorf("%v: %v", c.args, d)
		}
	}
	d := mustRun(t, "credential", "key", "create", "k1")
	if p, _ := d["path"].(string); !strings.HasPrefix(p, "sealed:") || d["type"] != "ssh-ed25519" {
		t.Errorf("the real run: %v", d)
	}
}
