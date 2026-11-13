package cli

import (
	"strings"
	"testing"
)

// The vault's key file is store.key since the sealed store: every hint
// that names it says so, the catalog's included (NO_PASSPHRASE, VAULT_KEY
// from a host's password reference).
func TestHintsNameTheStoreKeyFile(t *testing.T) {
	old := "vault" + ".key"
	for _, c := range errorCodes {
		if strings.Contains(c.Hint, old) {
			t.Errorf("%s hint names %s: %q", c.Code, old, c.Hint)
		}
	}
	for _, code := range []string{"NO_PASSPHRASE", "VAULT_KEY"} {
		found := false
		for _, c := range errorCodes {
			if c.Code == code {
				found = true
				if !strings.Contains(c.Hint, "store.key") {
					t.Errorf("%s hint does not name store.key: %q", code, c.Hint)
				}
			}
		}
		if !found {
			t.Errorf("%s is not in the catalog", code)
		}
	}
}
