package cli

import (
	"bufio"
	"encoding/base32"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `config approval-code` is not in the e2e (test/e2e/checks/coverage.sh says
// why): turning it on needs a person at a terminal who types the code from
// their phone. Here the terminal is played by a pipe, and the phone by
// totp() over the secret the command prints.

func approvalCodeOn(t *testing.T) bool {
	t.Helper()
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return st.Settings.ApprovalCode
}

// asPerson runs fn as a person at a terminal: stdin is a pipe that answer
// fills from what the command printed on stderr so far (up to the question).
func asPerson(t *testing.T, answer func(stderr string) string, fn func()) {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedIn, savedErr, savedInteractive := tcl.stdin, tcl.out.Err, tcl.terminal
	tcl.stdin, tcl.out.Err, tcl.terminal = inR, errW, true
	done := make(chan struct{})
	go func() { // the person reads the screen, then types at the question
		defer close(done)
		var seen strings.Builder
		r := bufio.NewReader(errR)
		for {
			s, err := r.ReadString(':')
			seen.WriteString(s)
			if strings.Contains(seen.String(), "Type the 6-digit code") {
				inW.WriteString(answer(seen.String()) + "\n")
				inW.Close()
				_, _ = r.WriteTo(&seen) // drain until the command is done
				return
			}
			if err != nil {
				inW.Close()
				return
			}
		}
	}()
	defer func() {
		tcl.stdin, tcl.out.Err, tcl.terminal = savedIn, savedErr, savedInteractive
		errW.Close()
		<-done
		inR.Close()
		errR.Close()
	}()
	fn()
}

// codeFor is what the authenticator app shows for the secret on screen.
func codeFor(t *testing.T, screen string) string {
	t.Helper()
	_, after, ok := strings.Cut(screen, "secret: ")
	if !ok {
		t.Errorf("no secret shown: %q", screen)
		return ""
	}
	line, _, _ := strings.Cut(after, "\n")
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(line, " ", ""))
	if err != nil {
		t.Errorf("secret %q: %v", line, err)
		return ""
	}
	return totp(raw, time.Now().Unix()/30)
}

// Only a person at a terminal can turn it on: the secret is shown once.
func TestApprovalCodeNeedsPerson(t *testing.T) {
	invHome(t)
	if e := wantCode(t, "NEEDS_PERSON", "config", "approval-code"); e.Exit != out.ExitPolicy {
		t.Errorf("script: exit %d", e.Exit)
	}
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	wantCode(t, "NEEDS_PERSON", "config", "approval-code")
	if approvalCodeOn(t) {
		t.Error("turned on")
	}
	if _, err := vault.Get(approvalSecret); err != vault.ErrNotFound {
		t.Errorf("a secret was stored: %v", err)
	}
}

// A wrong code changes nothing; the right one turns it on and keeps the
// secret in the vault.
func TestApprovalCodeOn(t *testing.T) {
	invHome(t)
	var e *out.Error
	asPerson(t, func(string) string { return "12345" }, func() { _, e = invRun(t, "config", "approval-code") })
	if e == nil || e.Code != "CODE_WRONG" || e.Exit != out.ExitUsage {
		t.Fatalf("wrong code: %+v", e)
	}
	if _, err := vault.Get(approvalSecret); err != vault.ErrNotFound || approvalCodeOn(t) {
		t.Fatalf("a wrong code changed something: %v", err)
	}
	var code string
	asPerson(t, func(screen string) string { code = codeFor(t, screen); return code }, func() {
		if d := mustRun(t, "config", "approval-code"); d["approval_code"] != "on" {
			t.Errorf("on: %v", d)
		}
	})
	if !approvalCodeOn(t) {
		t.Fatal("not on")
	}
	if s := approvalCodeSecret(); !codeOK(s, code, time.Now()) {
		t.Error("the stored secret is not the one shown")
	}
}

// Turning it off needs --yes and removes the secret.
func TestApprovalCodeOff(t *testing.T) {
	invHome(t)
	if err := vault.Set(store.Save, approvalSecret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(store.Save, func(st *store.State) error { st.Settings.ApprovalCode = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if e := wantCode(t, "SAFETY_SETTING", "config", "approval-code", "--off"); e.Exit != out.ExitPolicy {
		t.Errorf("exit %d", e.Exit)
	}
	if !approvalCodeOn(t) {
		t.Fatal("--off without --yes turned it off")
	}
	if d := mustRun(t, "config", "approval-code", "--off", "--yes"); d["approval_code"] != "off" {
		t.Errorf("off: %v", d)
	}
	if approvalCodeOn(t) {
		t.Error("still on")
	}
	if _, err := vault.Get(approvalSecret); err != vault.ErrNotFound {
		t.Errorf("the secret stayed: %v", err)
	}
}
