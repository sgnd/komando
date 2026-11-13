package vault

import (
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/cloud"
)

// O3: komando takes the secret stores' unlock values out of its
// environment at start, so no program it starts inherits them; it still
// reads them itself, and hands them to its own background processes on
// stdin (with the passphrase), never in their environment.
func TestUnlockEnvNotInherited(t *testing.T) {
	reset := func() {
		passMu.Lock()
		pass, unlock = "", map[string]string{}
		passMu.Unlock()
	}
	t.Cleanup(reset)
	reset()
	t.Setenv("KOMANDO_VAULT_PASS", "the-vault-passphrase")
	t.Setenv("KOMANDO_BW_PASSWORD", "bw-master-password")
	t.Setenv("VAULT_TOKEN", "hvs.token-value")
	TakeUnlockEnv()
	for _, kv := range os.Environ() {
		for _, n := range []string{"KOMANDO_VAULT_PASS=", "KOMANDO_BW_PASSWORD=", "VAULT_TOKEN="} {
			if strings.HasPrefix(kv, n) {
				t.Errorf("%s is still in the environment children get", n)
			}
		}
	}
	if cloud.UnlockEnv("KOMANDO_BW_PASSWORD") != "bw-master-password" || cloud.UnlockEnv("VAULT_TOKEN") != "hvs.token-value" {
		t.Fatal("komando no longer reads them")
	}
	if env := SelfEnv(); !slices.Contains(env, "KOMANDO_BW_PASSWORD=bw-master-password") || !slices.Contains(env, "KOMANDO_VAULT_PASS=the-vault-passphrase") {
		t.Errorf("SelfEnv: %v", env)
	}

	c := exec.Command("komando", "tunnel", "serve", "t-1")
	PassOnStdin(c)
	for _, kv := range c.Env {
		if strings.HasPrefix(kv, "KOMANDO_BW_PASSWORD=") || strings.HasPrefix(kv, "VAULT_TOKEN=") {
			t.Fatalf("background process environment has %s", kv)
		}
	}
	in, _ := io.ReadAll(c.Stdin)
	if strings.Contains(string(in), "bw-master-password") {
		t.Fatal("the value is on stdin as it is")
	}
	reset() // the background process starts with nothing
	if err := ReadPassStdin(strings.NewReader(string(in))); err != nil {
		t.Fatal(err)
	}
	if Passphrase() != "the-vault-passphrase" || cloud.UnlockEnv("KOMANDO_BW_PASSWORD") != "bw-master-password" || cloud.UnlockEnv("VAULT_TOKEN") != "hvs.token-value" {
		t.Fatalf("handed over: pass %q", Passphrase())
	}
	// the login holder's PASS line carries the same
	if h := Handoff(); !strings.HasPrefix(h, handoffMark) {
		t.Errorf("Handoff: %q", h)
	}
}

// O3: an env: reference to an unlock variable still resolves for a
// person after TakeUnlockEnv took it out of the environment.
func TestEnvRefToTakenUnlockVar(t *testing.T) {
	reset := func() {
		passMu.Lock()
		pass, unlock = "", map[string]string{}
		passMu.Unlock()
	}
	t.Cleanup(reset)
	reset()
	saved := RefGuard
	t.Cleanup(func() { RefGuard = saved })
	RefGuard = nil
	t.Setenv("VAULT_TOKEN", "hvs.token-value")
	t.Setenv("BAO_TOKEN", "bao-token-value")
	TakeUnlockEnv()
	for n, want := range map[string]string{"VAULT_TOKEN": "hvs.token-value", "BAO_TOKEN": "bao-token-value"} {
		if v, err := resolve("env:" + n); err != nil || v != want {
			t.Errorf("env:%s: %q %v", n, v, err)
		}
	}
	if _, err := resolve("env:KOMANDO_NO_SUCH_VAR_X"); err == nil {
		t.Error("an unset variable resolved")
	}
}
