package vault

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func TestPassphraseVaultMovesToStrongerKDF(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "correct horse battery staple")
	pass = ""
	Passphrase()
	defer func(n int) { PassphraseN = n }(PassphraseN)

	// a vault made before the cost was stored
	PassphraseN = legacyN
	if err := Set("db", "s3cret-value"); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	b, _ := os.ReadFile(store.Path("vault.json"))
	_ = json.Unmarshal(b, &raw)
	delete(raw, "scrypt_n")
	b, _ = json.Marshal(raw)
	if err := os.WriteFile(store.Path("vault.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	PassphraseN = 1 << 16
	s, err := Check()
	if err != nil || !s.OldKDF || s.ScryptN != legacyN || s.ShortPass {
		t.Fatalf("before: %+v %v", s, err)
	}
	if err := Set("api", "other-value"); err != nil {
		t.Fatal(err)
	}
	s, _ = Check()
	if s.OldKDF || s.ScryptN != 1<<16 {
		t.Fatalf("after: %+v", s)
	}
	for name, want := range map[string]string{"db": "s3cret-value", "api": "other-value"} {
		if v, err := Get(name); err != nil || v != want {
			t.Errorf("%s = %q, %v", name, v, err)
		}
	}
}

func TestShortPassphraseIsReported(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "short")
	pass = ""
	Passphrase()
	defer func(n int) { PassphraseN = n }(PassphraseN)
	PassphraseN = 1 << 10
	if err := Set("x", "value-1"); err != nil {
		t.Fatal(err)
	}
	if s, _ := Check(); !s.ShortPass {
		t.Errorf("%+v", s)
	}
}

// A mistyped passphrase must not save a secret under a second key.
func TestSetRefusesWrongPassphrase(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	defer func(n int) { PassphraseN = n }(PassphraseN)
	PassphraseN = legacyN // fast
	t.Setenv("KOMANDO_VAULT_PASS", "correct horse battery staple")
	pass = ""
	Passphrase()
	if err := Set("db", "s3cret-value"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_VAULT_PASS", "correct horse battery stapel")
	Passphrase()
	if err := Set("api", "other-value"); err == nil {
		t.Fatal("Set with a wrong passphrase succeeded")
	}
	t.Setenv("KOMANDO_VAULT_PASS", "correct horse battery staple")
	Passphrase()
	if v, err := Get("db"); err != nil || v != "s3cret-value" {
		t.Fatalf("Get db = %q, %v", v, err)
	}
	if _, err := Get("api"); err != ErrNotFound {
		t.Fatalf("api was saved: %v", err)
	}
}

// A lost vault.key is never replaced while secrets need it.
func TestMissingKeyFileIsNotRegenerated(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	pass = ""
	if err := Set("db", "s3cret-value"); err != nil {
		t.Fatal(err)
	}
	kp := store.Path("vault.key")
	if err := os.Remove(kp); err != nil {
		t.Fatal(err)
	}
	if _, err := Get("db"); err == nil {
		t.Fatal("Get without vault.key succeeded")
	}
	if err := Set("api", "other-value"); err == nil {
		t.Fatal("Set without vault.key succeeded")
	}
	if _, err := os.Stat(kp); !os.IsNotExist(err) {
		t.Fatalf("a new vault.key was made: %v", err)
	}
}

// A background komando process (tunnel serve) gets the passphrase on
// stdin, never in its environment, which stays in view while it runs.
func TestPassOnStdin(t *testing.T) {
	freshHome(t)
	setPass := func(p string) { passMu.Lock(); pass = p; passMu.Unlock() }
	t.Cleanup(func() { setPass("") })
	const want = "a long passphrase\nwith a line break"
	t.Setenv("KOMANDO_VAULT_PASS", want)
	Passphrase() // komando takes it out of its environment when it starts
	c := exec.Command("komando", "tunnel", "serve", "t-1")
	PassOnStdin(c)
	for _, e := range c.Env {
		if strings.HasPrefix(e, "KOMANDO_VAULT_PASS=") {
			t.Fatal("the passphrase is in the environment")
		}
	}
	if c.Args[len(c.Args)-1] != PassStdinFlag || c.Stdin == nil {
		t.Fatalf("args %q, stdin %v", c.Args, c.Stdin)
	}
	setPass("") // the child starts without it
	if err := ReadPassStdin(c.Stdin); err != nil || Passphrase() != want {
		t.Fatalf("read back %q: %v", Passphrase(), err)
	}
	setPass("") // a vault without a passphrase: no flag, nothing on stdin
	c = exec.Command("komando", "tunnel", "serve", "t-1")
	PassOnStdin(c)
	if c.Stdin != nil || len(c.Args) != 4 {
		t.Errorf("args %q, stdin %v", c.Args, c.Stdin)
	}
}
