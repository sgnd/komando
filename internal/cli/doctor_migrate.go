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

// The store moves to format 3 at the first open by a person at a
// terminal, or through komando's safety-tier approval window drawn by the
// signed bundled core; an AI agent or a script gets NEEDS_PERSON. The gate
// is one ordered table, first match wins (Audit E1-4):
//
//  1. an AI agent or an ssh-gate key: NEEDS_PERSON
//  2. CI set: NEEDS_PERSON
//  3. the command line not read yet (newCall's gate, promptFill): never
//     moves, as --dry-run is not known yet
//  4. --dry-run: never moves (doctor --dry-run shows what the move would do)
//  5. a person with stdin and stderr terminals and no SSH_CONNECTION or
//     SSH_TTY: the terminal path
//  6. `doctor`, not clickForgeable, no KOMANDO_NO_DIALOG: the window
//  7. everything else: NEEDS_PERSON
func migrateCallFor(cl *call, command string) store.MigrateCall {
	c := store.MigrateCall{Way: store.MigrateRefuse, RefGuard: vault.RefGuard}
	g := cl.gate()
	switch {
	case g.who.IsAgent():
		c.Why = "an AI agent (" + g.who.Agent + ")"
	case cl.getenv("CI") != "":
		c.Why = "a CI job"
	case !g.parsed || cl.noMove.Load():
		c.Why = "a look at the store before the command line was read"
	case g.dryRun:
		c.Why = "a dry run (`komando doctor --dry-run` shows what the move would do)"
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
