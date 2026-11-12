package cli

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// fillTest is a person at a terminal with an inventory: two servers, one
// of them protected, a database and a cache.
func fillTest(t *testing.T) {
	t.Helper()
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@10.0.0.5")
	mustRun(t, "host", "add", "prod1", "root@10.0.0.6", "--protected")
	mustRun(t, "conn", "add", "app-db", "postgres://app@10.0.0.9/app")
	mustRun(t, "conn", "add", "cache1", "redis://127.0.0.1:6379")
	saved := promptable
	promptable = func(string) bool { return true }
	t.Cleanup(func() { promptable = saved })
}

// What is missing is asked by its real name, added to the line, and the
// line shown is the line that runs.
func TestPromptFill(t *testing.T) {
	fillTest(t)
	for _, c := range []struct {
		args, answers []string
		want          string   // the filled line
		shows         []string // on the screen
	}{
		{[]string{"logs"}, []string{"web1"}, "logs web1", []string{"TARGET: ", "web1", "prod1"}},
		{[]string{"logs", "--since", "1h"}, []string{"1"}, "logs --since 1h prod1", nil},
		{[]string{"db", "query"}, []string{"select 1"}, "db query app-db 'select 1'", []string{"Using app-db (the only one of your databases)", "SQL: "}},
		{[]string{"db", "query", "app-db", "--file", "q.sql"}, nil, "db query app-db --file q.sql", nil}, // typed in full
		{[]string{"exec", "--", "uptime"}, []string{"web1", "y"}, "exec web1 -- uptime", []string{"Run it? [y/N, d = --dry-run first]"}},
		{[]string{"exec", "web1"}, []string{"df -h", "y"}, "exec web1 -- 'df -h'", []string{"COMMAND: "}},
		{[]string{"fs", "replace", "web1", "/etc/x", "--backup"}, []string{"a", "b", "y"}, "fs replace web1 /etc/x --backup --old=a --new=b", []string{"--old: "}},
		{[]string{"svc", "restart", "prod1"}, []string{"nginx"}, "svc restart prod1 nginx", nil}, // protected: the command asks, not Run it?
		{[]string{"cache", "rm", "cache1"}, []string{"k1", "cache1"}, "cache rm cache1 k1", []string{"This deletes the keys.", "Type cache1 to confirm"}},
		{[]string{"host", "rm", "--dry-run"}, []string{"web1"}, "host rm --dry-run web1", nil}, // a dry run runs at once
	} {
		drawn := promptFake(t, c.answers...)
		got, err := promptFill(c.args)
		if err != nil {
			t.Errorf("%v: %v\n%s", c.args, err, drawn)
			continue
		}
		if line := menuCommandLine(got); line != c.want {
			t.Errorf("%v: %s, want %s\n%s", c.args, line, c.want, drawn)
			continue
		}
		if !slices.Equal(got, c.args) && !strings.Contains(drawn.String(), "$ komando "+c.want+"\n") {
			t.Errorf("%v: the line that runs was not shown:\n%s", c.args, drawn)
		}
		for _, s := range c.shows {
			if !strings.Contains(drawn.String(), s) {
				t.Errorf("%v: %q not shown:\n%s", c.args, s, drawn)
			}
		}
		if slices.Equal(got, c.args) && drawn.Len() > 0 {
			t.Errorf("%v: typed in full, yet something was asked:\n%s", c.args, drawn)
		}
	}
}

// No to Run it?, a wrong name or Ctrl-C runs nothing.
func TestPromptFillCancel(t *testing.T) {
	fillTest(t)
	for _, c := range []struct{ args, answers []string }{
		{[]string{"exec", "web1"}, []string{"reboot", "n"}},
		{[]string{"exec", "web1"}, []string{"reboot", ""}}, // Enter is No
		{[]string{"cache", "rm", "cache1"}, []string{"k1", "cache"}},
		{[]string{"logs"}, nil}, // Ctrl-C at the first question
	} {
		promptFake(t, c.answers...)
		got, err := promptFill(c.args)
		var oe *out.Error
		if err == nil || got != nil {
			t.Errorf("%v %v: ran %v", c.args, c.answers, got)
		} else if e := promptStopped(err); !errors.As(e, &oe) || oe.Code != "CANCELLED" {
			t.Errorf("%v: %v", c.args, e)
		}
	}
}

// A protected server is never picked for the person, and with nothing to
// pick from komando says how to add one and stops.
func TestPromptFillPicks(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "prod1", "root@10.0.0.6", "--protected")
	saved := promptable
	promptable = func(string) bool { return true }
	defer func() { promptable = saved }()
	drawn := promptFake(t, "1")
	got, err := promptFill([]string{"facts"})
	if err != nil || menuCommandLine(got) != "facts prod1" || strings.Contains(drawn.String(), "Using") {
		t.Errorf("%v %v\n%s", got, err, drawn)
	}
	drawn = promptFake(t)
	if _, err := promptFill([]string{"db", "info"}); err == nil || !strings.Contains(drawn.String(), "No databases yet; add one: komando db add") {
		t.Errorf("%v\n%s", err, drawn)
	}
}

// Nobody but a person at a terminal is asked: the line stays as typed.
func TestPromptFillOnlyForAPerson(t *testing.T) {
	invHome(t)
	saved := promptable
	promptable = func(string) bool { return false }
	defer func() { promptable = saved }()
	if got, err := promptFill([]string{"logs"}); err != nil || !slices.Equal(got, []string{"logs"}) {
		t.Errorf("%v %v", got, err)
	}
}

// In a real terminal: a person who types `komando host show` is asked
// NAME, sees the line, and it runs; an AI agent in a terminal gets the
// usage error it always got, and nothing is asked.
func TestPromptFillAtATerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process")
	}
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@10.0.0.5")
	mustRun(t, "host", "add", "web2", "root@10.0.0.6")
	p := startPTYEnv(t, []string{"KOMANDO_PTY_AS=person"}, "host", "show")
	p.answer("NAME: ", "2\r")
	p.waitFor("$ komando host show web2")
	if code := p.exit(); code != 0 || !strings.Contains(p.shown(), "10.0.0.6") {
		t.Errorf("exit %d:\n%s", code, p.shown())
	}
	a := startPTYEnv(t, []string{"KOMANDO_PTY_AS=agent"}, "host", "show")
	if code := a.exit(); code != 2 || strings.Contains(a.shown(), "NAME: ") {
		t.Errorf("an agent: exit %d:\n%s", code, a.shown())
	}
}
