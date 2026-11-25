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
		{"doctor over ssh", "windows", false, map[string]string{"SSH_TTY": "/dev/pts/1"}, "doctor", store.MigrateRefuse},
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
