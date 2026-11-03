package vault

import (
	"encoding/json"
	"os"
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
