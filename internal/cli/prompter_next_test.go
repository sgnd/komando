package cli

import (
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
		for _, n := range h.next {
			check(key+" next", strings.ReplaceAll(n, "{}", "web1"))
		}
	}
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
	if !strings.Contains(drawn.String(), "COMMANDS\n  komando db info app-db") {
		t.Errorf("show: %s", drawn)
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
