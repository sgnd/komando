package cli

import (
	"strings"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The store moves to format 3 at the first open by a person at a
// terminal, or through komando's safety-tier approval window drawn by the
// signed bundled core; an AI agent or a script gets NEEDS_PERSON. The gate
// is one ordered table, first match wins (Audit E1-4):
//
//  1. an AI agent or an ssh-gate key: NEEDS_PERSON
//  2. CI set: NEEDS_PERSON
//  3. a person with stdin and stderr terminals and no SSH_CONNECTION or
//     SSH_TTY: the terminal path
//  4. `doctor`, not clickForgeable, no KOMANDO_NO_DIALOG: the window
//  5. everything else: NEEDS_PERSON
func migrateCallFor(cl *call, command string) store.MigrateCall {
	c := store.MigrateCall{Way: store.MigrateRefuse, RefGuard: vault.RefGuard}
	switch {
	case cl.isAgent():
		c.Why = "an AI agent (" + cl.caller().Agent + ")"
	case cl.getenv("CI") != "":
		c.Why = "a CI job"
	case cl.terminal && cl.getenv("SSH_CONNECTION") == "" && cl.getenv("SSH_TTY") == "":
		c.Way = store.MigrateTerminal
	case command == "doctor" && !clickForgeable(cl) && cl.getenv("KOMANDO_NO_DIALOG") == "":
		c.Way = store.MigrateWindow
		c.Ask = func(text string) bool {
			allowed, shown := cl.askPerson(text)
			return allowed && shown
		}
	default:
		c.Why = "a script or a call with no terminal"
	}
	if c.Way != store.MigrateRefuse {
		c.Alive = func(pid int, procStart string) bool {
			return netx.SessionAlive(&store.VpnSession{PID: pid, ProcStart: procStart})
		}
	}
	return c
}

// migrateCommand is the first word of the command line that is not a flag.
func migrateCommand(args []string) string {
	for _, a := range args[min(1, len(args)):] {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// migrateCaller is store.MigrateCaller: the one call running, as
// migrateCallFor says; with several calls running in this process, nobody
// migrates (the safest answer over every call, call_hooks.go).
func migrateCaller() store.MigrateCall {
	cl := soleCall()
	if cl == nil {
		return store.MigrateCall{Way: store.MigrateRefuse, Why: "a call beside other calls"}
	}
	return migrateCallFor(cl, migrateCommand(cl.args))
}
