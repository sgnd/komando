package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

const ptyNewPass = "a fresh and much longer passphrase"

// Neither a script nor an AI agent can change the vault's key: a
// passphrase it chose, or a key back in store.key, would let it open the
// vault on its own. No flag allows it.
func TestSecretPassphraseNeedsPerson(t *testing.T) {
	invHome(t)
	setSecret(t, "db-pass", "s3cret")
	raw, _ := os.ReadFile(store.Path(store.StoreFile))
	for _, agent := range []bool{false, true} {
		if agent {
			t.Setenv("KOMANDO_AGENT", "1")
			resetApproval()
			t.Cleanup(resetApproval)
		}
		for _, args := range [][]string{{"secret", "passphrase"}, {"secret", "passphrase", "--off", "--yes"}} {
			e := wantCode(t, "NEEDS_PERSON", args...)
			if e.Exit != out.ExitPolicy || strings.Contains(e.Hint, "add the flag") {
				t.Errorf("agent %v %v: %+v", agent, args, e)
			}
		}
		// a dry run is never blocked: it previews and names what the real run needs
		d := mustRun(t, "secret", "passphrase", "--dry-run")
		if d["dry_run"] != true || d["to"] != "passphrase" || d["secrets"] != float64(1) {
			t.Errorf("agent %v dry run: %v", agent, d)
		}
		if wb, _ := d["_meta"].(map[string]any)["would_be_blocked"].(map[string]any); wb["code"] != "NEEDS_PERSON" {
			t.Errorf("agent %v dry run would_be_blocked: %v", agent, d["_meta"])
		}
	}
	if now, _ := os.ReadFile(store.Path(store.StoreFile)); !bytes.Equal(raw, now) {
		t.Error("the store changed")
	}
}

func TestNewPassphraseProblem(t *testing.T) {
	for p, want := range map[string]string{
		"":                               "empty",
		"fourteen chars":                 "has 14 characters",
		" fifteen or more characters":    "space",
		"fifteen or more characters\t":   "space",
		"fifteen or more\x1b[200~ chars": "control characters",
		"correct horse battery staple":   "",
		"ünïcödé ünïcödé":                "", // 15 characters, more bytes
	} {
		got := newPassphraseProblem(p)
		if want == "" && got != "" || !strings.Contains(got, want) {
			t.Errorf("%q: %q, want %q", p, got, want)
		}
		if p != "" && strings.Contains(got, p) {
			t.Errorf("%q: the problem shows the passphrase", p)
		}
	}
}

// ptyVault is a vault with one secret under the passphrase invHome sets,
// with KOMANDO_VAULT_PASS set to pass for the komando the test starts.
func ptyVault(t *testing.T, pass string) []byte {
	t.Helper()
	invHome(t)
	setSecret(t, "db-pass", "s3cret value")
	t.Setenv("KOMANDO_VAULT_PASS", pass)         // komando took it out of its environment
	vault.ReadPassStdin(strings.NewReader(pass)) // and startPTY hands the child this one
	t.Cleanup(func() { vault.ReadPassStdin(strings.NewReader("test-passphrase-long-enough")) })
	raw, err := os.ReadFile(store.Path(store.StoreFile))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// opensWith: the store, as komando reads it from disk, opens with pass
// (its key file, when it has no passphrase). The child komando changed the
// key, so this process's open store and key are not asked.
func opensWith(t *testing.T, pass string) error {
	t.Helper()
	return vault.Opens(pass)
}

func TestPTYSecretPassphrase(t *testing.T) {
	ptyVault(t, "test-passphrase-long-enough")
	p := startPTY(t, "secret", "passphrase")
	p.answer("New vault passphrase (hidden): ", ptyNewPass+"\r")
	p.answer("Type it again (hidden): ", ptyNewPass+"\r")
	if code := p.exit(); code != 0 {
		t.Fatalf("exit %d; the screen:\n%s", code, p.shown())
	}
	p.waitFor("Re-encrypted 1 secret:")
	screen := p.shown()
	if strings.Contains(screen, ptyNewPass) || !strings.Contains(screen, "put the new passphrase in KOMANDO_VAULT_PASS") {
		t.Errorf("the screen:\n%s", screen)
	}
	if strings.Contains(screen, "Current vault passphrase") {
		t.Errorf("asked for the current passphrase although KOMANDO_VAULT_PASS opens the vault:\n%s", screen)
	}
	if err := opensWith(t, ptyNewPass); err != nil {
		t.Fatal(err)
	}
	if err := opensWith(t, "test-passphrase-long-enough"); err == nil {
		t.Error("the old passphrase still opens the vault")
	}
	// the audit log, read by a komando that opens the store with the new key
	t.Setenv("KOMANDO_VAULT_PASS", ptyNewPass)
	vault.ReadPassStdin(strings.NewReader(ptyNewPass))
	a := startPTY(t, "audit", "-n", "0", "--command", "secret.", "-o", "json")
	if code := a.exit(); code != 0 {
		t.Fatalf("audit: exit %d\n%s", code, a.shown())
	}
	if b := a.shown(); !strings.Contains(b, `secret.passphrase`) || strings.Contains(b, ptyNewPass) {
		t.Errorf("audit: %s", b)
	}
}

// KOMANDO_VAULT_PASS holds the new passphrase already: komando asks for the
// one the vault has now.
func TestPTYSecretPassphraseAsksCurrent(t *testing.T) {
	ptyVault(t, ptyNewPass)
	p := startPTY(t, "secret", "passphrase")
	p.answer("Current vault passphrase (hidden): ", "test-passphrase-long-enough\r")
	p.answer("New vault passphrase (hidden): ", ptyNewPass+"\r")
	p.answer("Type it again (hidden): ", ptyNewPass+"\r")
	if code := p.exit(); code != 0 {
		t.Fatalf("exit %d; the screen:\n%s", code, p.shown())
	}
	if err := opensWith(t, ptyNewPass); err != nil {
		t.Fatal(err)
	}
}

// A wrong current passphrase, a short one or two that differ: nothing
// changes.
func TestPTYSecretPassphraseChangesNothing(t *testing.T) {
	for _, c := range []struct {
		name, code string
		typed      []string // question, answer
	}{
		{"wrong current", "WRONG_PASSPHRASE", []string{"Current vault passphrase (hidden): ", "not the passphrase\r"}},
		{"too short", "WEAK_PASSPHRASE", []string{"New vault passphrase (hidden): ", "short\r"}},
		{"mismatch", "PASSPHRASE_MISMATCH", []string{"New vault passphrase (hidden): ", ptyNewPass + "\r", "Type it again (hidden): ", ptyNewPass + "!\r"}},
	} {
		env := "test-passphrase-long-enough"
		if c.code == "WRONG_PASSPHRASE" {
			env = "something else entirely"
		}
		raw := ptyVault(t, env)
		p := startPTY(t, "secret", "passphrase")
		for i := 0; i < len(c.typed); i += 2 {
			p.answer(c.typed[i], c.typed[i+1])
		}
		if code := p.exit(); code != out.ExitUsage {
			t.Errorf("%s: exit %d; the screen:\n%s", c.name, code, p.shown())
		}
		p.waitFor("nothing was changed")
		if !strings.Contains(p.shown(), c.code) {
			t.Errorf("%s: want %s; the screen:\n%s", c.name, c.code, p.shown())
		}
		if now, _ := os.ReadFile(store.Path(store.StoreFile)); !bytes.Equal(raw, now) {
			t.Errorf("%s: the store changed", c.name)
		}
	}
}

// --off takes the passphrase away: a new random key in store.key, after a
// person's yes.
func TestPTYSecretPassphraseOff(t *testing.T) {
	ptyVault(t, "test-passphrase-long-enough")
	p := startPTY(t, "secret", "passphrase", "--off")
	p.answer("[y/N] ", "y\r")
	if code := p.exit(); code != 0 {
		t.Fatalf("exit %d; the screen:\n%s", code, p.shown())
	}
	p.waitFor("remove KOMANDO_VAULT_PASS")
	if fi, err := os.Stat(store.Path("store.key")); err != nil || fi.Size() != 32 {
		t.Fatalf("store.key: %v %v", fi, err)
	}
	if err := opensWith(t, "anything at all, it is not used now"); err != nil {
		t.Fatal(err)
	}
	if s, err := vault.Check(); err != nil || s.Mode != "keyfile" {
		t.Errorf("%+v %v", s, err)
	}
}

// doctor fails when KOMANDO_VAULT_PASS does not open the vault (changed
// without `secret passphrase`).
func TestDoctorVaultKey(t *testing.T) {
	ptyVault(t, "test-passphrase-long-enough")
	checks := func() map[string]securityCheck {
		vault.Passphrase()
		st, err := loadState()
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]securityCheck{}
		for _, c := range securityChecks(st) {
			m[c.Name] = c
		}
		return m
	}
	if c, ok := checks()["security:vault_key"]; ok {
		t.Errorf("the right passphrase: %+v", c)
	}
	t.Setenv("KOMANDO_VAULT_PASS", "a changed passphrase, not re-encrypted")
	c := checks()["security:vault_key"]
	if c.OK || c.Warning || !strings.Contains(c.Detail, "komando secret passphrase") {
		t.Errorf("a changed passphrase: %+v", c)
	}
}
