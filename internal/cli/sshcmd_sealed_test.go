package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// On a sealed home, OpenSSH needs files komando keeps sealed: an agent is
// refused, a person gets a private known_hosts copy, and a sealed key
// stops it with a hint to use komando shell.
func TestSSHCommandSealedHome(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	store.UseSealedForNewHomes(true)
	t.Cleanup(func() { store.UseSealedForNewHomes(os.Getenv("KOMANDO_TEST_SEALED") == "1") })
	for _, a := range agentVars {
		t.Setenv(a.env, "")
		resetApproval()
		os.Unsetenv(a.env)
		resetApproval()
	}
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1")
	d := mustRun(t, "host", "ssh-command", "web1")
	cmd, _ := d["command"].(string)
	i := strings.Index(cmd, "UserKnownHostsFile=")
	if i < 0 || strings.Contains(cmd, store.Path("known_hosts")) {
		t.Fatalf("command %q", cmd)
	}
	kh := strings.Fields(cmd[i+len("UserKnownHostsFile="):])[0]
	if fi, err := os.Stat(kh); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("known_hosts copy %s: %v", kh, err)
	}

	mustRun(t, "key", "gen", "k1")
	mustRun(t, "host", "edit", "web1", "--key", "k1")
	if _, e := invRun(t, "host", "ssh-command", "web1"); e == nil || e.Code != "NOT_SUPPORTED" || !strings.Contains(e.Hint, "komando shell") {
		t.Fatalf("sealed key: %+v", e)
	}

	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	if _, e := invRun(t, "host", "ssh-command", "web1"); e == nil || e.Code != "NEEDS_PERSON" {
		t.Fatalf("agent: %+v", e)
	}
}

// config show and doctor name the sealed store on a sealed home.
func TestSealedConfigAndDoctor(t *testing.T) {
	invHome(t)
	store.UseSealedForNewHomes(true)
	t.Cleanup(func() { store.UseSealedForNewHomes(os.Getenv("KOMANDO_TEST_SEALED") == "1") })
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1")
	c := mustRun(t, "config", "show")
	files := c["files"].(map[string]any)
	for _, k := range []string{"state", "vault", "known_hosts", "audit"} {
		if files[k] != store.Path(store.StoreFile) {
			t.Errorf("files.%s = %v", k, files[k])
		}
	}
	d, _ := invRun(t, "doctor")
	found := false
	sec, _ := d["security"].([]any)
	for _, ch := range sec {
		m := ch.(map[string]any)
		if m["name"] == "security:vault" && strings.Contains(m["detail"].(string), store.StoreFile) {
			found = true
		}
	}
	if !found {
		t.Errorf("doctor does not name the store: %v", sec)
	}
}

// Accepting an old copy is for a person at a terminal.
func TestAcceptOldCopyNeedsAPerson(t *testing.T) {
	invHome(t)
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	if _, e := invRun(t, "doctor", "--accept-old-copy"); e == nil || e.Code != "NEEDS_PERSON" {
		t.Fatalf("agent: %+v", e)
	}
}
