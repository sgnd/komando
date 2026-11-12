package cli

import (
	"slices"
	"strings"
	"testing"
)

// Every command komando suggests to a person (komando alone, the COMMANDS
// after a show, Next:) is a real command line that parses.
func TestSuggestedCommandsParse(t *testing.T) {
	check := func(source, line string) {
		formParse(t, source, formSplitWords(strings.TrimPrefix(strings.TrimSpace(line), "$ komando ")))
	}
	for _, l := range strings.Split(personHelp(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "$ komando ") {
			check("komando alone", l)
		}
	}
	for kind, cmds := range itemCommands {
		for _, c := range cmds {
			check("show "+kind, strings.ReplaceAll(c, "{}", "web1"))
		}
	}
	for key, h := range formHints {
		if len(h.next) > 3 {
			t.Errorf("%s: %d Next: lines, at most 3", key, len(h.next))
		}
		for _, n := range h.next {
			check(key+" next", strings.ReplaceAll(n, "{}", "web1"))
		}
	}
	// a hint, a show command and a suggestion name real commands, and a
	// suggestion never brings in an approval
	root := newRoot()
	for _, keys := range [][]string{mapKeys(formHints), mapKeys(showKinds)} {
		for _, key := range keys {
			if c, _, err := root.Find(strings.Fields(key)); err != nil || commandKey(c) != key {
				t.Errorf("%q is not a command", key)
			}
		}
	}
	for kind, cmds := range itemCommands {
		for _, c := range cmds {
			for _, f := range []string{"yes", "allow-dangerous", "reveal"} {
				if strings.Contains(c, "--"+f) {
					t.Errorf("show %s: %q adds --%s", kind, c, f)
				}
			}
		}
	}
	for key, h := range formHints {
		for _, n := range h.next {
			for _, f := range []string{"yes", "allow-dangerous", "reveal"} {
				if strings.Contains(n, "--"+f) {
					t.Errorf("%s next: %q adds --%s", key, n, f)
				}
			}
		}
	}
	// every list is shown for some item
	shown := map[string]bool{}
	for _, k := range showKinds {
		shown[k] = true
	}
	for kind := range itemCommands {
		if base, _, _ := strings.Cut(kind, ":"); !shown[kind] && !slices.Contains([]string{"server", "swarm", "conn", "db", "cache", "queue", "storage", "cluster", "registry", "vpn"}, base) {
			t.Errorf("itemCommands[%q] is never shown", kind)
		}
	}
}

// An area's Next: lines join the questions given for the same command in
// another file, in either order; two next lists for one command are a
// mistake.
func TestFormHintsNextMerge(t *testing.T) {
	saved := formHints
	defer func() { formHints = saved }()
	formHints = map[string]formHint{}
	addFormHints(map[string]formHint{"a": {next: []string{"x"}}})
	addFormHints(map[string]formHint{"a": {hide: []string{"f"}}, "b": {hide: []string{"g"}}})
	addFormHints(map[string]formHint{"b": {next: []string{"y"}}})
	if a, b := formHints["a"], formHints["b"]; len(a.next) != 1 || len(a.hide) != 1 || len(b.next) != 1 || len(b.hide) != 1 {
		t.Fatalf("not merged: %+v %+v", a, b)
	}
	defer func() {
		if recover() == nil {
			t.Error("a second next list for one command was taken")
		}
	}()
	addFormHints(map[string]formHint{"a": {next: []string{"z"}}})
}

// komando alone, for a person: the groups, START first, and with nothing
// added yet the way to add something.
func TestPersonHelp(t *testing.T) {
	invHome(t)
	h := personHelp()
	if !strings.Contains(h, "Nothing added yet: komando host add") || strings.Index(h, "START") > strings.Index(h, "SERVERS") {
		t.Errorf("%s", h)
	}
	mustRun(t, "host", "add", "web1", "root@10.0.0.5")
	if strings.Contains(personHelp(), "Nothing added yet") {
		t.Error("an inventory with a server is called empty")
	}
}

// After a run that ended well, a person sees the line to type next time
// and what usually comes next; nobody else sees anything.
func TestPromptNext(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "app-db", "postgres://app@10.0.0.9/app")
	drawn := promptFake(t)
	fillSeen = fillInfo{person: true, key: "db add", first: "app-db", prompted: true, line: []string{"db", "add", "app-db", "postgres://app@10.0.0.9/app"}}
	defer func() { fillSeen = fillInfo{} }()
	promptNext()
	for _, want := range []string{"Next time: komando db add app-db postgres://app@10.0.0.9/app", "Next: komando db info app-db · komando db query app-db"} {
		if !strings.Contains(drawn.String(), want) {
			t.Errorf("%q not in:\n%s", want, drawn)
		}
	}
	drawn.Reset()
	fillSeen = fillInfo{person: true, key: "conn show", first: "app-db"}
	promptNext()
	if !strings.Contains(drawn.String(), "COMMANDS\n  komando db query app-db \"select 1\"") {
		t.Errorf("show: %s", drawn)
	}
	// a sqlite conn gets its own list, a key its own, and both end there
	mustRun(t, "conn", "add", "notes", "sqlite:///tmp/notes.db")
	for _, c := range []struct{ key, first, want, not string }{
		{"conn show", "notes", "komando db dump notes --to backup.sql", "db user list"},
		{"conn show", "notes", "komando conn rm notes", "db activity"},
		{"key show", "deploy", "komando key deploy deploy TARGET", "db "},
		{"job status", "7f3", "komando job logs 7f3 --limit 50", "conn "},
		{"group rm", "old", "Next: komando group add old TARGET...", "group rm"},
	} {
		drawn.Reset()
		fillSeen = fillInfo{person: true, key: c.key, first: c.first}
		promptNext()
		if !strings.Contains(drawn.String(), c.want) || strings.Contains(drawn.String(), c.not) {
			t.Errorf("%s %s: %s", c.key, c.first, drawn)
		}
	}
	// a Next: line that needs the first argument is left out without one
	drawn.Reset()
	fillSeen = fillInfo{person: true, key: "vpn down"}
	promptNext()
	if got := drawn.String(); !strings.Contains(got, "Next: komando vpn status\n") {
		t.Errorf("vpn down alone: %q", got)
	}
	drawn.Reset()
	fillSeen = fillInfo{key: "db add", first: "app-db", prompted: true}
	promptNext()
	if drawn.Len() > 0 {
		t.Errorf("printed for someone who is not a person at a terminal: %s", drawn)
	}
}

// A person told there is nothing yet is given the add command to type,
// never a menu that is gone.
func TestAddHintForAPerson(t *testing.T) {
	saved := interactive
	interactive = func() bool { return true }
	defer func() { interactive = saved }()
	for family, want := range map[string]string{"db": "komando db add", "host": "komando host add", "vpn": "komando vpn add"} {
		if h := addHint(family, ""); !strings.Contains(h, want) || strings.Contains(h, "pick Add") {
			t.Errorf("%s: %q", family, h)
		}
	}
}

// `komando --help` groups the commands as `komando` alone does, so a
// person finds each one under the same heading in both.
func TestHelpGroupsMatchPersonHelp(t *testing.T) {
	root := newRoot()
	title := map[string]string{}
	for _, g := range root.Groups() {
		title[g.ID] = strings.ToUpper(strings.TrimSuffix(g.Title, ":"))
	}
	for _, l := range strings.Split(personHelp(), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !slices.Contains([]string{"SERVERS", "DATA", "PLATFORM", "ACCESS", "OVERVIEW", "SETUP"}, f[0]) {
			continue
		}
		for _, name := range f[1:] {
			c, _, err := root.Find([]string{name})
			if err != nil || c == root {
				t.Errorf("%s: %q is not a command", f[0], name)
				continue
			}
			if got := title[c.GroupID]; got != f[0] {
				t.Errorf("%s is under %q in --help, %q in komando alone", name, got, f[0])
			}
		}
	}
}
