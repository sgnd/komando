package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/store"
)

// Cut step E1: the store moves to format 3 at the first open by a person
// at a terminal, or through komando's safety-tier approval window drawn by
// the signed bundled core; an AI agent or a script gets NEEDS_PERSON
// (update-flow note 3.3, conditions b and e).
func TestMigrateCallFor(t *testing.T) {
	old := desktopOS
	t.Cleanup(func() { desktopOS = old })
	cases := []struct {
		name     string
		os       string
		terminal bool
		env      map[string]string
		command  string
		want     store.MigrateWay
	}{
		{"person at a terminal", "darwin", true, nil, "list", store.MigrateTerminal},
		{"agent at a terminal", "darwin", true, map[string]string{"CLAUDECODE": "1"}, "list", store.MigrateRefuse},
		{"agent runs doctor with no terminal (UR4)", "windows", false, map[string]string{"CLAUDECODE": "0"}, "doctor", store.MigrateRefuse},
		{"ssh-gate key", "darwin", true, map[string]string{engine.GateEnv: "phone"}, "doctor", store.MigrateRefuse},
		{"script, any command", "windows", false, nil, "list", store.MigrateRefuse},
		{"app runs doctor", "windows", false, nil, "doctor", store.MigrateWindow},
		{"app runs doctor, no dialog", "windows", false, map[string]string{"KOMANDO_NO_DIALOG": "1"}, "doctor", store.MigrateRefuse},
		{"app runs doctor in CI", "windows", false, map[string]string{"CI": "true"}, "doctor", store.MigrateRefuse},
		{"person at a terminal in CI", "darwin", true, map[string]string{"CI": "true"}, "list", store.MigrateRefuse},
		{"person at a terminal over ssh, a command", "darwin", true, map[string]string{"SSH_CONNECTION": "10.0.0.1 22 10.0.0.2 22"}, "list", store.MigrateRefuse},
		{"person at a terminal over ssh, doctor (row 5; the window then cannot show)", "windows", true, map[string]string{"SSH_TTY": "/dev/pts/1"}, "doctor", store.MigrateWindow},
		{"doctor on a desktop where a click is forgeable", "linux", false, map[string]string{"DISPLAY": ":0"}, "doctor", store.MigrateRefuse},
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
			}, nil)
			parsedGate(t, cl, c.command)
			got := migrateCallFor(cl, c.command)
			if got.Way != c.want {
				t.Fatalf("way %d, want %d (why %q)", got.Way, c.want, got.Why)
			}
			if got.Way == store.MigrateRefuse && strings.TrimSpace(got.Why) == "" {
				t.Error("a refusal that does not say who asked")
			}
			if got.Way == store.MigrateWindow && got.Ask == nil {
				t.Error("the window path without a window")
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
	if c := migrateCallFor(cl, "doctor"); c.Way != store.MigrateRefuse || !strings.Contains(c.Why, "before the command line") {
		t.Fatalf("the line not read yet: way %d, why %q", c.Way, c.Why)
	}
	parsedGate(t, cl, line...)
	if c := migrateCallFor(cl, "doctor"); c.Way != store.MigrateRefuse || !strings.Contains(c.Why, "dry run") {
		t.Fatalf("the line read, --dry-run: way %d, why %q", c.Way, c.Why)
	}
	cl = person()
	parsedGate(t, cl, "doctor")
	cl.noMove.Store(true)
	if c := migrateCallFor(cl, "doctor"); c.Way != store.MigrateRefuse {
		t.Fatalf("while promptFill looks: way %d, why %q", c.Way, c.Why)
	}
	cl.noMove.Store(false)
	if c := migrateCallFor(cl, "doctor"); c.Way != store.MigrateTerminal {
		t.Fatalf("doctor read, at a terminal: way %d, why %q", c.Way, c.Why)
	}
}
