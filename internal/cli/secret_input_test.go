package cli

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// O8: masking each exact vault value told an AI agent which of its guesses
// is a secret (`secret show GUESS`, `exec web1 -- echo GUESS` printed
// [secret:NAME] on a hit). An agent's arguments and input that hold a
// vault value are refused, a dry run too, the refusal is audited, and the
// message names no secret.
func TestAgentInputWithVaultValueRefused(t *testing.T) {
	invHome(t)
	saved := tcl.out
	tcl.out = &out.Printer{Format: "json", W: tcl.out.W, Start: time.Now()} // the vault values are read once per printer
	t.Cleanup(func() { tcl.out = saved })
	const v = "Tr0ub4dor-guess-77"
	if err := vault.Set(store.Save, "db-pass", v); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "CLAUDECODE", "1")

	for _, args := range [][]string{
		{"secret", "show", v},
		{"secret", "show", v, "--dry-run"},
		{"host", "show", "x" + v + "x"},
		{"exec", "web1", "--", "echo", v},
		{"exec", "web1", "-e", "X=" + v, "--", "true"},
	} {
		e := wantCode(t, "SECRET_INPUT_INVALID", args...)
		if strings.Contains(e.Message, "db-pass") || strings.Contains(e.Message, v) {
			t.Errorf("%v: the message names the secret: %q", args, e.Message)
		}
	}
	if err := hiddenInInput(tcl, "run.sh", []byte("#!/bin/sh\necho '"+v+"'\n")); err == nil || !strings.Contains(err.Error(), "SECRET_INPUT_INVALID") && toErr(err).Code != "SECRET_INPUT_INVALID" {
		t.Errorf("a script with the value: %v", err)
	}
	// a guess that is no secret goes on as before
	wantCode(t, "SECRET_NOT_FOUND", "secret", "show", "not-a-secret-guess")

	// the person sees the guessing in the audit log
	noAgent(t)
	d := mustRun(t, "audit", "--limit", "20")
	if got := fmt.Sprint(d); strings.Count(got, "SECRET_INPUT_INVALID") < 5 || strings.Contains(got, v) {
		t.Errorf("audit log: %s", got)
	}
	// a person types what they like
	wantCode(t, "SECRET_NOT_FOUND", "secret", "show", v)
}
