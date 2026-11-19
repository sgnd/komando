package cli

import (
	"encoding/base32"
	"errors"
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

// With an approval code on (Linux, BSD, Windows), an agent's --yes needs the right code typed in
// the window; a click alone, or a wrong code, is not enough.
func TestApprovalNeedsTheCode(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long")
	secret := []byte("12345678901234567890")
	if err := vault.Set(store.Save(), approvalSecret, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(store.Save(), func(st *store.State) error { st.Settings.ApprovalCode = true; return nil }); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	savedA, savedC, savedOS := askOnScreen, askCodeOnScreen, desktopOS
	defer func() {
		askOnScreen, askCodeOnScreen, desktopOS = savedA, savedC, savedOS
		tcl.flags.yes = false
		resetApproval()
	}()
	desktopOS = "linux" // macOS asks for the device owner instead (approval_owner_test.go)
	askOnScreen = func(*call, string) (bool, bool) { t.Error("the plain window was used"); return true, true }
	for typed, want := range map[string]bool{"": false, "123456": false, "now": true} {
		resetApproval()
		code := typed
		if typed == "now" {
			code = totp(secret, time.Now().Unix()/30)
		}
		askCodeOnScreen = func(*call, string) (string, bool, bool) { return code, true, true }
		tcl.flags.yes = true
		if got := tcl.yesOK(); got != want {
			t.Errorf("code %q: allowed %v, want %v", typed, got, want)
		}
		if !want && tcl.sess.Window().Why != "wrong-code" {
			t.Errorf("code %q: why %q", typed, tcl.sess.Window().Why)
		}
	}
}

// A code works once: a second window in the same 30 s, the code of an
// earlier step (a phone clock behind), and a code older than the last one
// taken are refused; the next step's code works (C10).
func TestApprovalCodeOnce(t *testing.T) {
	setHome(t, t.TempDir())
	secret := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)
	step := now.Unix() / 30
	if ok, used := codeAccepted(secret, totp(secret, step), now); !ok || used {
		t.Fatalf("first use: %v %v", ok, used)
	}
	if ok, used := codeAccepted(secret, totp(secret, step), now.Add(10*time.Second)); ok || !used {
		t.Errorf("same code again: %v %v", ok, used)
	}
	if ok, used := codeAccepted(secret, totp(secret, step-1), now); ok || !used {
		t.Errorf("the step before (clock skew): %v %v", ok, used)
	}
	if ok, _ := codeAccepted(secret, "000000", now); ok {
		t.Error("a wrong code")
	}
	// a phone ahead: the next step's code is taken, then the current one is older
	if ok, _ := codeAccepted(secret, totp(secret, step+1), now); !ok {
		t.Error("the next step")
	}
	if ok, used := codeAccepted(secret, totp(secret, step), now.Add(30*time.Second)); ok || !used {
		t.Errorf("older than the last taken: %v %v", ok, used)
	}
	st, err := store.Load()
	if err != nil || st.Settings.ApprovalCodeStep != step+1 {
		t.Fatalf("stored step %d, %v", st.Settings.ApprovalCodeStep, err)
	}
}

// An older store copy put back by hand would forget the last step; the
// store refuses to open it (STORE_OLD_COPY), so no code is taken from it.
func TestApprovalCodeOnceOldCopy(t *testing.T) {
	setHome(t, t.TempDir())
	secret := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)
	step := now.Unix() / 30
	if ok, _ := codeAccepted(secret, totp(secret, step-1), now); !ok {
		t.Fatal("first")
	}
	store.Close()
	saved := store.GenerationKeeper
	t.Cleanup(func() { store.GenerationKeeper = saved; store.Close() })
	// the keychain remembers a newer change than the store has
	store.GenerationKeeper = store.GenerationKeep{
		Get: func() (uint64, bool, error) { return 1 << 40, true, nil },
		Set: func(uint64) error { return errors.New("read only") },
		Del: func() {},
	}
	if ok, used := codeAccepted(secret, totp(secret, step), now); ok || used {
		t.Errorf("the old copy took a code: %v %v", ok, used)
	}
}
