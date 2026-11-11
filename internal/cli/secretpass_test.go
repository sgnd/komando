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
// passphrase it chose, or a key back in vault.key, would let it open the
// vault on its own. No flag allows it.
func TestSecretPassphraseNeedsPerson(t *testing.T) {
	invHome(t)
	setSecret(t, "db-pass", "s3cret")
	raw, _ := os.ReadFile(store.Path("vault.json"))
	for _, agent := range []bool{false, true} {
		if agent {
			t.Setenv("KOMANDO_AGENT", "1")
			resetApproval()
			t.Cleanup(resetApproval)
		}
		for _, args := range [][]string{{"secret", "passphrase"}, {"secret", "passphrase", "--off", "--yes"}, {"secret", "passphrase", "--dry-run"}} {
			e := wantCode(t, "NEEDS_PERSON", args...)
			if e.Exit != out.ExitPolicy || strings.Contains(e.Hint, "add the flag") {
				t.Errorf("agent %v %v: %+v", agent, args, e)
			}
		}
	}
	if now, _ := os.ReadFile(store.Path("vault.json")); !bytes.Equal(raw, now) {
		t.Error("vault.json changed")
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
	t.Setenv("KOMANDO_VAULT_PASS", pass) // komando took it out of its environment
	raw, err := os.ReadFile(store.Path("vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// opensWith: the vault, as komando reads it from disk, opens with pass.
func opensWith(t *testing.T, pass string) error {
	t.Helper()
	t.Setenv("KOMANDO_VAULT_PASS", pass)
	vault.Passphrase()
	v, err := vault.Get("db-pass")
	if err == nil && v != "s3cret value" {
		t.Errorf("db-pass = %q", v)
	}
	return err
}

func TestPTYSecretPassphrase(t *testing.T) {
	filesOnly(t)
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
	b, _ := os.ReadFile(store.Path("audit.jsonl"))
	if !strings.Contains(string(b), `"secret.passphrase"`) || strings.Contains(string(b), ptyNewPass) {
		t.Errorf("audit: %s", b)
	}
}

// KOMANDO_VAULT_PASS holds the new passphrase already: komando asks for the
// one the vault has now.
func TestPTYSecretPassphraseAsksCurrent(t *testing.T) {
	filesOnly(t)
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
	filesOnly(t)
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
		if now, _ := os.ReadFile(store.Path("vault.json")); !bytes.Equal(raw, now) {
			t.Errorf("%s: vault.json changed", c.name)
		}
	}
}

// --off takes the passphrase away: a new random key in vault.key, after a
// person's yes.
func TestPTYSecretPassphraseOff(t *testing.T) {
	filesOnly(t)
	ptyVault(t, "test-passphrase-long-enough")
	p := startPTY(t, "secret", "passphrase", "--off")
	p.answer("[y/N] ", "y\r")
	if code := p.exit(); code != 0 {
		t.Fatalf("exit %d; the screen:\n%s", code, p.shown())
	}
	p.waitFor("remove KOMANDO_VAULT_PASS")
	if fi, err := os.Stat(store.Path("vault.key")); err != nil || fi.Size() != 32 {
		t.Fatalf("vault.key: %v %v", fi, err)
	}
	if err := opensWith(t, "anything at all, it is not used now"); err != nil {
		t.Fatal(err)
	}
	if s, err := vault.Check(); err != nil || s.Mode != "keyfile" {
		t.Errorf("%+v %v", s, err)
	}
}

// doctor fails when KOMANDO_VAULT_PASS does not open the vault (changed
// without `secret passphrase`), and warns about a vault.key nothing uses.
func TestDoctorVaultKey(t *testing.T) {
	filesOnly(t)
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
	if err := os.WriteFile(store.Path("vault.key"), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := checks()["security:vault_key_file"]; !c.Warning || !strings.Contains(c.Detail, "old copies") {
		t.Errorf("a leftover vault.key: %+v", c)
	}
}
