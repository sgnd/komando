package cli

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// O8: masking each exact vault value told an AI agent which of its guesses
// is a secret (`secret show GUESS`, `exec web1 -- echo GUESS` printed
// [credential:NAME] on a hit), and refusing such input told it the same
// (SECRET_INPUT_INVALID on a hit, the usual answer on a miss). An agent's
// input that holds a vault value now gets the answer any other value gets:
// the value it typed is not hidden in that command's output. The person
// still sees the guessing in the audit log.
func TestAgentInputWithVaultValueAnsweredAsAnyOther(t *testing.T) {
	invHome(t)
	saved := tcl.out
	tcl.out = &out.Printer{Format: "json", W: tcl.out.W, Start: time.Now()} // the vault values are read once per printer
	t.Cleanup(func() { tcl.out = saved })
	const v = "Tr0ub4dor-guess-77"
	if err := vault.Set(store.Save(), "db-pass", v); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	for _, pair := range [][2][]string{
		{{"host", "ssh", "show", v}, {"host", "ssh", "show", "Tr0ub4dor-wrong-77"}},
		{{"credential", "password", "show", v}, {"credential", "password", "show", "Tr0ub4dor-wrong-77"}},
		{{"credential", "password", "show", v, "--dry-run"}, {"credential", "password", "show", "Tr0ub4dor-wrong-77", "--dry-run"}},
	} {
		_, hit := invRun(t, pair[0]...)
		_, miss := invRun(t, pair[1]...)
		if hit == nil || miss == nil || hit.Code != miss.Code || strings.Contains(hit.Message, "credential:db-pass") {
			t.Errorf("%v: hit %+v, miss %+v", pair[0], hit, miss)
		}
	}
	if err := hiddenInInput(tcl, "run.sh", []byte("#!/bin/sh\necho '"+v+"'\n")); err != nil {
		t.Errorf("a script with the value: %v", err)
	}
	// the person sees the guessing in the audit log
	noAgent(t)
	d := mustRun(t, "audit", "list", "--limit", "20")
	if got := fmt.Sprint(d); strings.Count(got, "secret_value_in_input") < 3 || strings.Contains(got, v) {
		t.Errorf("audit log: %s", got)
	}
}

// C654: a value typed after a secret's name is refused as SECRET_IN_ARGS,
// with the shell-history warning, before the count of the arguments, on
// every leaf that reads a secret's value; nothing is saved. One row per
// leaf: secretValueLeaves lists them.
func TestSecretValueInArgsRefusedFirst(t *testing.T) {
	for _, tc := range []struct{ id, hint string }{
		{"credential.password.add", "--from-env"},
		{"credential.token.add", "--from-env"},
		{"secret.check", "type it"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			invHome(t)
			if tc.id == "secret.check" {
				t.Setenv("PW", "s3cret-value-1")
				mustRun(t, "credential", "password", "add", "db-pass", "--from-env", "PW")
			}
			args := append(strings.Split(tc.id, "."), "db-pass", "hunter22-typed")
			e := wantCode(t, "SECRET_IN_ARGS", args...)
			again := "run `komando " + strings.Join(args[:len(args)-1], " ") + "` and type it (hidden)"
			if !strings.Contains(e.Message, "shell history") || !strings.Contains(e.Hint, tc.hint) || !strings.HasPrefix(e.Hint, again) || strings.Contains(e.Message+e.Hint, "hunter22") {
				t.Errorf("%+v", e)
			}
			if tc.id != "secret.check" {
				if _, err := vault.Get("db-pass"); err == nil {
					t.Error("a value on the command line was saved")
				}
			}
		})
	}
	for id := range secretValueLeaves {
		if !slices.Contains([]string{"credential.password.add", "credential.token.add", "secret.check"}, id) {
			t.Errorf("%s reads a secret's value but has no row here", id)
		}
	}
}
