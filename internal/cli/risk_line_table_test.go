package cli

import (
	"strings"
	"testing"
)

// TestRiskOfLineTable pins the tier an AI agent's command line gets, line by
// line. The tiers and notes are what today's code answers for each line
// (recorded by running it), not what a design says: a change to how a
// line is matched to its command, or to a tier, fails here. riskOfLine
// reads only the line, so protection of a target (a --yes on a protected
// host) is not part of the answer.
func TestRiskOfLineTable(t *testing.T) {
	tests := []struct {
		name string
		line string
		args []string // the words, when a word holds a space; else line is split on spaces
		tier tier
		note string // the row's wording: what, dynamic, bulk or typed
	}{
		{"exec is rated by the command it runs", "exec web1 -- rm -rf /var/www", nil, tierDangerous, "the command matches a destructive rule"},
		// pins today; C353 may lower it with Audit
		{"a bool flag before a positional", "exec --read-only web1 -- df -h", nil, tierDangerous, "the command matches a destructive rule"},
		{"fs rm", "fs rm web1 /tmp/x", nil, tierDangerous, "deletes the files"},
		{"cache rm", "cache rm c1 k", nil, tierDangerous, "deletes the keys"},
		{"cluster scale to 0", "cluster scale prod deploy/app 0", nil, tierDangerous, "stops every copy of the app"},
		{"cluster scale to 3", "cluster scale prod deploy/app 3", nil, tierChange, ""},
		{"a --yes on a host rm does not change the tier", "host rm web1 --yes", nil, tierChange, ""},
		{"protection off", "host edit web1 --protected=false", nil, tierSafety, "turns protection off"},
		{"an alias", "host ls", nil, tierRead, ""},
		{"a plural", "servers list", nil, tierRead, ""},
		{"removing an essential package", "pkg rm web1 openssh-server", nil, tierDangerous, "removes a package the server needs to run or to let you in"},
		{"removing another package", "pkg rm web1 htop", nil, tierChange, "removes the packages"},
		{"a security upgrade", "pkg upgrade web1 --security", nil, tierDangerous, "an update would remove a package the server needs"},
		{"a SQL query", "db query prod DROP TABLE x", nil, tierDangerous, "the query deletes data (DROP, DELETE without WHERE, KILL, ...)"},
		{"secret rm", "secret rm token", nil, tierDangerous, "deletes the saved passwords"},
		{"group rm asks for a bulk confirm", "group rm big", nil, tierChange, "deleting a group of more than 3 members"},
		{"policy rm", "policy rm deny1", nil, tierSafety, "removes a deny rule"},
		{"a rule switched on", "policy edit r --off=false", nil, tierChange, ""},
		{"a rule switched on for some servers", "policy edit r --rm-server web1", nil, tierChange, ""},
		{"a rule switched off", "policy edit r --off", nil, tierSafety, "switches a rule off"},
		{"--off in another spelling", "policy edit r --off=true --add-server web1", nil, tierSafety, "switches a rule off"},
		{"--off=false, then the last value off", "policy edit r --off=false --off", nil, tierSafety, "switches a rule off"},
		{"a line that does not parse is rated by its words", "policy edit r --off=false --off --bogus", nil, tierSafety, "switches a rule off"},
		{"a shell is for a person", "shell web1", nil, tierPerson, ""},
		{"a host key reset is for a person", "host trust web1 --reset", nil, tierPerson, "replaces a pinned host key"},
		{"a line that names no command is for a person (cut PR B2)", "nosuchcommand", nil, tierPerson, ""},
		{"a global flag before the command", "-o json fs rm web1 /tmp/x", nil, tierDangerous, "deletes the files"},
		{"a proxy command on a host", "", []string{"host", "ssh", "edit", "web1", "--proxy-command", "nc %h %p"}, tierSafety, "an AI agent runs it (the proxy command runs on this computer)"},
		{"a group selector", "exec @prod -- rm -rf /var/www", nil, tierDangerous, "the command matches a destructive rule"},
		{"a sudo flag before --", "exec web1 --sudo -- userdel bob", nil, tierDangerous, "the command matches a destructive rule"},
		{"--reveal is not a tier of its own", "secret show token --reveal", nil, tierRead, ""},
	}
	if len(tests) != 31 {
		t.Fatalf("%d lines, want 31", len(tests))
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			words := tt.args
			if words == nil {
				words = strings.Fields(tt.line)
			}
			r := riskOfLine(words)
			note := ""
			for _, s := range []string{r.what, r.dynamic, r.bulk, r.typed} {
				if s != "" {
					note = s
					break
				}
			}
			if r.tier != tt.tier || note != tt.note {
				t.Errorf("riskOfLine(%q) = tier %s, %q; want tier %s, %q", words, r.tier, note, tt.tier, tt.note)
			}
		})
	}
}

// A caller that never set the command tree must not get a read for a
// line: every line is a step for a person, whether it names a command or not.
func TestRiskOfLineNilTreeFailsClosed(t *testing.T) {
	saved := commandTree
	t.Cleanup(func() { commandTree = saved })
	commandTree = nil
	for _, line := range []string{"cache rm c1 k", "host ls", "version", "no such command", ""} {
		if r := riskOfLine(strings.Fields(line)); r.tier != tierPerson {
			t.Errorf("riskOfLine(%q) with no tree = tier %s, want %s", line, r.tier, tierPerson)
		}
	}
	if c, words, pos := lineWords([]string{"cache", "rm", "c1", "k"}); c != nil || words != nil || pos != nil {
		t.Errorf("lineWords with no tree = %v %v %v, want nothing", c, words, pos)
	}
	commandTree = saved
	if r := riskOfLine([]string{"host", "ssh", "list"}); r.tier != tierRead {
		t.Errorf("riskOfLine(host ls) with the tree = tier %s, want read", r.tier)
	}
}

// A line that names no command is for a person (cut PR B2), as at the ssh
// gate: an unknown word, or words after a group that name nothing under
// it. komando alone (first steps) and a group alone stay what they are.
func TestRiskOfLineNamesNoCommand(t *testing.T) {
	for _, line := range []string{"nosuchcommand", "hots list", "host frobnicate web1", "db user frobnicate pg", "-o json nosuchcommand"} {
		if r := riskOfLine(strings.Fields(line)); r.tier != tierPerson {
			t.Errorf("riskOfLine(%q) = tier %s, want %s", line, r.tier, tierPerson)
		}
	}
	for _, line := range []string{"", "-o json", "host", "db user", "host --help"} {
		if r := riskOfLine(strings.Fields(line)); r.tier != tierRead {
			t.Errorf("riskOfLine(%q) = tier %s, want %s", line, r.tier, tierRead)
		}
	}
}
