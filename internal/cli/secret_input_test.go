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
// [secret:NAME] on a hit), and refusing such input told it the same
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
		{{"host", "show", v}, {"host", "show", "Tr0ub4dor-wrong-77"}},
		{{"secret", "show", v}, {"secret", "show", "Tr0ub4dor-wrong-77"}},
		{{"secret", "show", v, "--dry-run"}, {"secret", "show", "Tr0ub4dor-wrong-77", "--dry-run"}},
	} {
		_, hit := invRun(t, pair[0]...)
		_, miss := invRun(t, pair[1]...)
		if hit == nil || miss == nil || hit.Code != miss.Code || strings.Contains(hit.Message, "secret:db-pass") {
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
