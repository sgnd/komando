package cli

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/store"
)

// Cut step E1: the store moves to format 3 only from `komando doctor`,
// typed by a person at a terminal (a y/N) or run by the app through
// komando's safety-tier approval window; every other command, an AI agent
// or a script gets NEEDS_PERSON (update-flow note 3.3, conditions b and e;
// chief, 2026-11-27: only doctor moves it).
func TestMigrateCallFor(t *testing.T) {
	old := desktopOS
	t.Cleanup(func() { desktopOS = old })
	cases := []struct {
		name     string
		os       string
		terminal bool
		env      map[string]string
		line     []string
		want     store.MigrateWay
	}{
		{"person at a terminal, doctor", "darwin", true, nil, []string{"doctor"}, store.MigrateTerminal},
		{"person at a terminal, -o json doctor", "darwin", true, nil, []string{"-o", "json", "doctor"}, store.MigrateTerminal},
		{"person at a terminal, list", "darwin", true, nil, []string{"list"}, store.MigrateRefuse},
		{"person at a terminal, completion zsh (.zshrc)", "darwin", true, nil, []string{"completion", "zsh"}, store.MigrateRefuse},
		{"person at a terminal, version", "darwin", true, nil, []string{"version"}, store.MigrateRefuse},
		{"person at a terminal, komando alone", "darwin", true, nil, nil, store.MigrateRefuse},
		{"agent at a terminal", "darwin", true, map[string]string{"CLAUDECODE": "1"}, []string{"doctor"}, store.MigrateRefuse},
		{"agent runs doctor with no terminal (UR4)", "windows", false, map[string]string{"CLAUDECODE": "0"}, []string{"doctor"}, store.MigrateRefuse},
		{"ssh-gate key", "darwin", true, map[string]string{engine.GateEnv: "phone"}, []string{"doctor"}, store.MigrateRefuse},
		{"script, any command", "windows", false, nil, []string{"list"}, store.MigrateRefuse},
		{"app runs doctor", "windows", false, nil, []string{"doctor"}, store.MigrateWindow},
		{"app runs list", "windows", false, nil, []string{"list"}, store.MigrateRefuse},
		{"app runs doctor, no dialog", "windows", false, map[string]string{"KOMANDO_NO_DIALOG": "1"}, []string{"doctor"}, store.MigrateRefuse},
		{"app runs doctor in CI", "windows", false, map[string]string{"CI": "true"}, []string{"doctor"}, store.MigrateRefuse},
		{"person at a terminal in CI", "darwin", true, map[string]string{"CI": "true"}, []string{"doctor"}, store.MigrateRefuse},
		{"person at a terminal over ssh, a command", "darwin", true, map[string]string{"SSH_CONNECTION": "10.0.0.1 22 10.0.0.2 22"}, []string{"list"}, store.MigrateRefuse},
		{"person at a terminal over ssh, doctor (row 5; the window then cannot show)", "windows", true, map[string]string{"SSH_TTY": "/dev/pts/1"}, []string{"doctor"}, store.MigrateWindow},
		{"doctor on a desktop where a click is forgeable", "linux", false, map[string]string{"DISPLAY": ":0"}, []string{"doctor"}, store.MigrateRefuse},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			desktopOS = c.os
			env := c.env
			cl := newCall(engine.Call{
				Program:   "komando",
				LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
				Environ:   func() []string { return nil },
				Terminal:  c.terminal,
				Ancestors: func() string { return "" },
			}, c.line)
			parsedGate(t, cl, c.line...)
			got := migrateCallFor(cl)
			if got.Way != c.want {
				t.Fatalf("way %d, want %d (why %q)", got.Way, c.want, got.Why)
			}
			if got.Way == store.MigrateRefuse && strings.TrimSpace(got.Why) == "" {
				t.Error("a refusal that does not say who asked")
			}
			if got.Way != store.MigrateRefuse && got.Ask == nil {
				t.Error("a move with no question to the person")
			}
			if got.Way != store.MigrateRefuse && got.Alive == nil {
				t.Error("no way to see running komando processes")
			}
		})
	}
}

// parsedGate starts the command line args in cl as the root's
// PersistentPreRunE does: the gate is made from the parsed line.
func parsedGate(t *testing.T, cl *call, args ...string) {
	t.Helper()
	cmd, rest, err := newRoot(cl).Find(args)
	if err == nil {
		err = cmd.ParseFlags(rest)
	}
	if err != nil {
		t.Fatal(err)
	}
	cl.begin(cmd)
}

// P0 of 2026-11-27: a person's `doctor --dry-run` at a terminal moved the
// store, as promptFill opened it before the line was parsed and --dry-run
// read false. Before the line is read, and while promptFill looks, the
// store never moves.
func TestMigrateCallForUnreadLine(t *testing.T) {
	line := []string{"doctor", "--dry-run"}
	person := func() *call {
		return newCall(engine.Call{
			Program:   "komando",
			LookupEnv: func(string) (string, bool) { return "", false },
			Environ:   func() []string { return nil },
			Terminal:  true,
			Ancestors: func() string { return "" },
		}, line)
	}
	cl := person()
	if c := migrateCallFor(cl); c.Way != store.MigrateRefuse || !strings.Contains(c.Why, "before the command line") {
		t.Fatalf("the line not read yet: way %d, why %q", c.Way, c.Why)
	}
	parsedGate(t, cl, line...)
	if c := migrateCallFor(cl); c.Way != store.MigrateRefuse || !strings.Contains(c.Why, "dry run") {
		t.Fatalf("the line read, --dry-run: way %d, why %q", c.Way, c.Why)
	}
	cl = person()
	parsedGate(t, cl, "doctor")
	cl.noMove.Store(true)
	if c := migrateCallFor(cl); c.Way != store.MigrateRefuse {
		t.Fatalf("while promptFill looks: way %d, why %q", c.Way, c.Why)
	}
	cl.noMove.Store(false)
	if c := migrateCallFor(cl); c.Way != store.MigrateTerminal {
		t.Fatalf("doctor read, at a terminal: way %d, why %q", c.Way, c.Why)
	}
}

// At the terminal the person reads the plan and answers one y/N, default
// no (chief, 2026-11-27: typing doctor to check health never moves the
// store by itself); the answer holds for the rest of the command.
func TestAskMoveOnce(t *testing.T) {
	for _, c := range []struct {
		typed string
		want  bool
	}{{"y\n", true}, {"n\n", false}, {"\n", false}, {"", false}} {
		t.Run(fmt.Sprintf("typed %q", c.typed), func(t *testing.T) {
			var e bytes.Buffer
			cl := newCall(engine.Call{
				Program:   "komando",
				LookupEnv: func(string) (string, bool) { return "", false },
				Environ:   func() []string { return nil },
				Terminal:  true,
				Stdin:     strings.NewReader(c.typed),
				Stderr:    &e,
				Ancestors: func() string { return "" },
			}, []string{"doctor"})
			parsedGate(t, cl, "doctor")
			ask := migrateCallFor(cl).Ask
			if got := ask("THE PLAN"); got != c.want {
				t.Fatalf("%v, want %v", got, c.want)
			}
			if got := ask("THE PLAN"); got != c.want {
				t.Fatalf("asked again: %v", got)
			}
			if s := e.String(); strings.Count(s, "Move the store to format 3 now? [y/N]") != 1 || strings.Count(s, "THE PLAN") != 1 {
				t.Fatalf("the screen\n%s", s)
			}
		})
	}
}

// Rule R3 (C606): before the move, doctor lists each v0.17 job record with
// no end (ID, server, command name, start) and marks them ended on the
// person's yes: all at once, or one by one. A caller the move refuses is
// asked nothing.
func TestDoctorOldJobs(t *testing.T) {
	started := time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)
	jobs := []store.OldJob{
		{ID: "j1", Host: "web", Name: "pg_dump", Started: started, Folder: "$HOME/.komando/jobs/j1"},
		{ID: "j3", Host: "db", Name: "sleep\x1b[2J", Started: started, Folder: "$HOME/.komando/jobs/j3"},
	}
	saved, savedEnd := oldJobs, endOldJobs
	t.Cleanup(func() { oldJobs, endOldJobs = saved, savedEnd })
	for _, c := range []struct {
		name  string
		typed string
		agent bool
		want  []string // the IDs marked; nil: nothing is marked
	}{
		{"all at once", "y\n", false, []string{"j1", "j3"}},
		{"one by one", "n\ny\nn\n", false, []string{"j1"}},
		{"none", "n\nn\nn\n", false, nil},
		{"an AI agent", "y\n", true, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			listed := false
			oldJobs = func(context.Context) ([]store.OldJob, error) { listed = true; return jobs, nil }
			var marked []string
			var markedBy string
			endOldJobs = func(_ context.Context, ids []string, by string) error {
				marked, markedBy = ids, by
				return nil
			}
			vars := map[string]string{"KOMANDO_ACTOR": "alice"}
			if c.agent {
				vars["CLAUDECODE"] = "1"
			}
			env := func(k string) (string, bool) { v, ok := vars[k]; return v, ok }
			var e bytes.Buffer
			cl := newCall(engine.Call{
				Program:   "komando",
				LookupEnv: env,
				Environ:   func() []string { return nil },
				Terminal:  true,
				Stdin:     iotest.OneByteReader(strings.NewReader(c.typed)), // a terminal gives a line per answer
				Stderr:    &e,
				Ancestors: func() string { return "" },
			}, []string{"doctor"})
			parsedGate(t, cl, "doctor")
			if err := doctorOldJobs(cl, t.Context()); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(marked, c.want) {
				t.Fatalf("marked %v, want %v\n%s", marked, c.want, e.String())
			}
			// audit A3: the person who answered is on the mark, not komando
			if len(c.want) > 0 && markedBy != "alice" {
				t.Errorf("marked by %q, want the person who answered: alice", markedBy)
			}
			if c.agent {
				if listed || e.Len() > 0 {
					t.Fatalf("an agent was shown the jobs:\n%s", e.String())
				}
				return
			}
			for _, want := range []string{"j1", "web", "pg_dump", "2026-11-20 09:30", "j3", "db", "sleep", "Mark all 2 ended? [y/N]",
				"komando cannot see whether one still runs on its server: look there first, by the server and the command below."} {
				if !strings.Contains(e.String(), want) {
					t.Errorf("the screen lacks %q:\n%s", want, e.String())
				}
			}
			if strings.Contains(e.String(), "\x1b") {
				t.Errorf("a control character reached the terminal: %q", e.String())
			}
		})
	}
}
