package cli

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// RFC 6238 appendix B, SHA-1, 8 digits there; the last 6 digits are the
// 6-digit code.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want8 := range map[int64]string{59: "94287082", 1111111109: "07081804", 1234567890: "89005924", 2000000000: "69279037"} {
		if got := totp(secret, unix/30); got != want8[2:] {
			t.Errorf("t=%d: %s, want %s", unix, got, want8[2:])
		}
	}
	now := time.Unix(1234567890, 0)
	if !codeOK(secret, "005924", now) || !codeOK(secret, totp(secret, now.Unix()/30-1), now) || codeOK(secret, "000000", now) || codeOK(secret, "", now) {
		t.Error("codeOK")
	}
}

// With an approval code on, an agent's --yes needs the right code typed in
// the window; a click alone, or a wrong code, is not enough.
func TestApprovalNeedsTheCode(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long")
	secret := []byte("12345678901234567890")
	if err := vault.Set(approvalSecret, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(st *store.State) error { st.Settings.ApprovalCode = true; return nil }); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDECODE", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	savedA, savedC := askOnScreen, askCodeOnScreen
	defer func() { askOnScreen, askCodeOnScreen = savedA, savedC; g.yes = false; resetApproval() }()
	askOnScreen = func(string) (bool, bool) { t.Error("the plain window was used"); return true, true }
	for typed, want := range map[string]bool{"": false, "123456": false, "now": true} {
		resetApproval()
		code := typed
		if typed == "now" {
			code = totp(secret, time.Now().Unix()/30)
		}
		askCodeOnScreen = func(string) (string, bool, bool) { return code, true, true }
		g.yes = true
		if got := yesOK(); got != want {
			t.Errorf("code %q: allowed %v, want %v", typed, got, want)
		}
		if !want && cur().sess.Window().Why != "wrong-code" {
			t.Errorf("code %q: why %q", typed, cur().sess.Window().Why)
		}
	}
}
