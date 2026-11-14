package cli

import (
	"os"
	"path/filepath"
	"regexp"
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
	root := newRoot(tcl)
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
	tcl.nextNow = nil
	mustRun(t, "conn", "add", "app-db", "postgres://app@10.0.0.9/app")
	drawn := promptFake(t)
	tcl.fillSeen = fillInfo{person: true, key: "db add", first: "app-db", prompted: true, line: []string{"db", "add", "app-db", "postgres://app@10.0.0.9/app"}}
	defer func() { tcl.fillSeen = fillInfo{} }()
	promptNext(tcl)
	for _, want := range []string{"Next time: komando db add app-db postgres://app@10.0.0.9/app", "Next: komando db info app-db · komando db query app-db"} {
		if !strings.Contains(drawn.String(), want) {
			t.Errorf("%q not in:\n%s", want, drawn)
		}
	}
	drawn.Reset()
	tcl.fillSeen = fillInfo{person: true, key: "conn show", first: "app-db"}
	promptNext(tcl)
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
		{"tunnel show", "db-tunnel", "komando tunnel stop db-tunnel", "conn "},
		{"recipe show", "health", "komando recipe run health TARGET", "conn "},
	} {
		drawn.Reset()
		tcl.fillSeen = fillInfo{person: true, key: c.key, first: c.first}
		promptNext(tcl)
		if !strings.Contains(drawn.String(), c.want) || strings.Contains(drawn.String(), c.not) {
			t.Errorf("%s %s: %s", c.key, c.first, drawn)
		}
	}
	// a Next: line that needs the first argument is left out without one
	drawn.Reset()
	tcl.fillSeen = fillInfo{person: true, key: "vpn down"}
	promptNext(tcl)
	if got := drawn.String(); !strings.Contains(got, "Next: komando vpn status\n") {
		t.Errorf("vpn down alone: %q", got)
	}
	drawn.Reset()
	tcl.fillSeen = fillInfo{key: "db add", first: "app-db", prompted: true}
	promptNext(tcl)
	if drawn.Len() > 0 {
		t.Errorf("printed for someone who is not a person at a terminal: %s", drawn)
	}
}

// A person told there is nothing yet is given the add command to type,
// never a menu that is gone.
func TestAddHintForAPerson(t *testing.T) {
	saved := tcl.terminal
	tcl.terminal = true
	defer func() { tcl.terminal = saved }()
	for family, want := range map[string]string{"db": "komando db add", "host": "komando host add", "vpn": "komando vpn add"} {
		if h := addHint(tcl, family, ""); !strings.Contains(h, want) || strings.Contains(h, "pick Add") {
			t.Errorf("%s: %q", family, h)
		}
	}
}

// `komando --help` groups the commands as `komando` alone does, so a
// person finds each one under the same heading in both.
func TestHelpGroupsMatchPersonHelp(t *testing.T) {
	root := newRoot(tcl)
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

// Nothing next goes to stdout (S-9.3): the commands to run next are
// data.next for agents and one Next: line on stderr for a person, which
// only promptNext prints.
func TestNextOnlyOnStderr(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	more, _ := filepath.Glob("../out/*.go")
	stdoutNext := regexp.MustCompile(`"(\\n)?([Nn]ext|follow it with|try it|undo it|wait for them all): `)
	for _, f := range append(files, more...) {
		if strings.HasSuffix(f, "_test.go") || f == "prompter_next.go" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range strings.Split(string(b), "\n") {
			if stdoutNext.MatchString(l) {
				t.Errorf("%s:%d: a next line outside promptNext: %s", f, i+1, strings.TrimSpace(l))
			}
		}
	}
	// a command that worked out its next lines puts them in the Next: line
	invHome(t)
	drawn := promptFake(t)
	tcl.fillSeen = fillInfo{person: true, key: "job start", first: "web1"}
	defer func() { tcl.fillSeen, tcl.nextNow = fillInfo{}, nil }()
	jobStarted{Jobs: []started{{ID: "j1", Host: "web1", OK: true}}}.withNext(tcl)
	promptNext(tcl)
	if got := drawn.String(); got != "Next: komando job logs j1 --limit 20 · komando job wait j1 · komando job status j1\n" {
		t.Errorf("job start: %q", got)
	}
}

// S-9.4: every add, edit, rename and rm has a Next: list, from its formHint
// or its verb: add -> test, show; edit -> show, test; rename -> show NEW;
// rm -> list. Each line is a command that parses.
func TestStandardNextPerVerb(t *testing.T) {
	for _, c := range allCommands(newRoot(tcl)) {
		if !c.Runnable() || c.Hidden {
			continue
		}
		key := commandKey(c)
		w := strings.Fields(key)
		if !slices.Contains([]string{"add", "edit", "rename", "rm"}, w[len(w)-1]) {
			continue
		}
		lines := nextLines(key, "web1", []string{"web1", "web2"})
		if len(lines) == 0 {
			t.Errorf("%s: no Next: line (S-9.4); give it a formHint next or a show/list command", key)
			continue
		}
		for _, l := range lines {
			formParse(t, key+" next", formSplitWords(strings.TrimPrefix(l, "komando ")))
		}
	}
	for key, want := range map[string]string{
		"host add":    "komando test web1",
		"conn add":    "komando test web1",
		"host rename": "komando host show web2",
		"key rename":  "komando key show web2",
		"rename":      "komando list web2",
		"user add":    "komando user list web1",
		"cron rm":     "komando cron list web1",
		"host rm":     "komando host list",
		"vpn edit":    "komando vpn show web1",
	} {
		if got := nextLines(key, "web1", []string{"web1", "web2"}); len(got) == 0 || got[0] != want {
			t.Errorf("%s: Next: %q, want %q first", key, got, want)
		}
	}
}
