package cli

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The store moves to format 3 only from `komando doctor`, typed by a
// person at a terminal or run by the Komando app with komando's safety-tier
// approval window drawn by the signed bundled core, and only after the
// person is shown the plan and says yes. Every other command, an AI agent
// and a script get NEEDS_PERSON, and nothing changes. The gate is one
// ordered table, first match wins (Audit E1-4):
//
//  1. an AI agent or an ssh-gate key: NEEDS_PERSON
//  2. CI set: NEEDS_PERSON
//  3. not the parsed command `doctor` (any other command, a line not read
//     yet, promptFill): NEEDS_PERSON
//  4. --dry-run: never moves (doctor --dry-run shows what the move would do)
//  5. a person with stdin and stderr terminals and no SSH_CONNECTION or
//     SSH_TTY: the plan and a y/N at the terminal
//  6. not clickForgeable, no KOMANDO_NO_DIALOG: the plan in the window
//  7. everything else: NEEDS_PERSON
func migrateCallFor(cl *call) store.MigrateCall {
	c := store.MigrateCall{Way: store.MigrateRefuse, RefGuard: vault.RefGuard}
	g := cl.gate()
	switch {
	case g.who.IsAgent():
		c.Why = "an AI agent (" + g.who.Agent + ")"
	case cl.getenv("CI") != "":
		c.Why = "a CI job"
	case g.cmdID != "doctor" || cl.noMove.Load():
		c.Why = notDoctor(g.cmdID)
	case g.dryRun:
		c.Why = "a dry run (`komando doctor --dry-run` shows what the move would do)"
	case cl.terminal && cl.getenv("SSH_CONNECTION") == "" && cl.getenv("SSH_TTY") == "":
		c.Way = store.MigrateTerminal
		c.Ask = func(plan string) bool {
			return answerMove(cl, func() bool {
				fmt.Fprintln(cl.out.Err, plan)
				return confirmYes(cl, "Move the store to format 3 now?")
			})
		}
	case !clickForgeable(cl) && cl.getenv("KOMANDO_NO_DIALOG") == "":
		c.Way = store.MigrateWindow
		c.Ask = func(plan string) bool {
			return answerMove(cl, func() bool {
				allowed, shown := cl.askPerson(strings.ReplaceAll(plan, "\n", " "))
				return allowed && shown
			})
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

// notDoctor names the command that may not move the store, for the
// refusal: "`komando list`", or a look before the line was read.
func notDoctor(id string) string {
	switch id {
	case "", "doctor": // doctor here: promptFill looks before the line is read
		return "a look at the store before the command line was read"
	case "komando":
		return "`komando` with no command"
	}
	return "`komando " + strings.ReplaceAll(id, ".", " ") + "`"
}

// answerMove is the person's answer to the move (ask shows the plan and
// asks: a y/N at the terminal, default no, or the window). It holds for the
// rest of the command: the store opens more than once in one command, and
// a no is not asked again.
func answerMove(cl *call, ask func() bool) bool {
	if cl.moveAnswer == 0 {
		cl.moveAnswer = -1
		if ask() {
			cl.moveAnswer = 1
		}
	}
	return cl.moveAnswer == 1
}

// migrateCaller is store.MigrateCaller: the one call running, as
// migrateCallFor says; with several calls running in this process, nobody
// migrates (the safest answer over every call, call_hooks.go).
func migrateCaller() store.MigrateCall {
	cl := soleCall()
	if cl == nil {
		return store.MigrateCall{Way: store.MigrateRefuse, Why: "a call beside other calls"}
	}
	return migrateCallFor(cl)
}

// migrationPreview is doctor --dry-run on a store that has not moved to
// format 3 yet: what the move would do, in counts, read without writing.
type migrationPreview struct{ store.MigrationPreview }

// doctorDryRunMove prints the preview and reports true when the store has
// still to move; a store of format 3 (or none) goes on to doctor's checks.
func doctorDryRunMove(cl *call, ctx context.Context) (bool, error) {
	pv, err := store.PreviewMigration(ctx, vault.RefGuard)
	if err != nil {
		return true, toErr(err)
	}
	if pv.Format != "1" && pv.Format != "2" {
		return false, nil
	}
	cl.out.Print("doctor", migrationPreview{pv}, nil)
	return true, nil
}

func (m migrationPreview) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "store: format %s\n", m.Format)
	if m.WouldMove {
		fmt.Fprintf(&b, "the move to format 3 would go ahead; backup first: %s\n", m.Backup)
	} else {
		b.WriteString("the move to format 3 would stop:\n")
		for _, r := range m.WouldRefuse {
			fmt.Fprintf(&b, "  ✗ %s\n", r)
		}
		if len(m.Fix) > 0 {
			b.WriteString("to fix it:\n")
			for i, s := range m.Fix {
				fmt.Fprintf(&b, "  %d. %s\n", i+1, s)
			}
		}
	}
	b.WriteString("records (now → after):\n")
	for _, k := range slices.Sorted(maps.Keys(m.Counts)) {
		c := m.Counts[k]
		fmt.Fprintf(&b, "  %-16s %5d → %d\n", k, c[0], c[1])
	}
	fmt.Fprintf(&b, "names changed %d, fields rewritten %d, servers with a key and a password %d, snippets with an old reference %d, groups merged %d\n",
		m.NamesChanged, m.FieldsRewritten, m.KeyAndPassword, m.SnippetsWithOldRef, m.MergedGroups)
	b.WriteString("checked only by the move itself:\n")
	for _, n := range m.NotChecked {
		fmt.Fprintf(&b, "  - %s\n", n)
	}
	b.WriteString("nothing was written\n")
	return b.String()
}
