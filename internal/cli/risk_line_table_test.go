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
		tier tier
		note string // the row's wording: what, dynamic, bulk or typed
	}{
		{"exec is rated by the command it runs", "exec web1 -- rm -rf /var/www", tierDangerous, "the command matches a destructive rule"},
		{"a bool flag before a positional", "exec --read-only web1 -- df -h", tierDangerous, "the command matches a destructive rule"},
		{"fs rm", "fs rm web1 /tmp/x", tierDangerous, "deletes the files"},
		{"cache rm", "cache rm c1 k", tierDangerous, "deletes the keys"},
		{"cluster scale to 0", "cluster scale prod deploy/app 0", tierDangerous, "stops every copy of the app"},
		{"cluster scale to 3", "cluster scale prod deploy/app 3", tierChange, ""},
		{"a --yes on a host rm does not change the tier", "host rm web1 --yes", tierChange, ""},
		{"protection off", "host edit web1 --protected=false", tierSafety, "turns protection off"},
		{"an alias", "host ls", tierRead, ""},
		{"a plural", "servers list", tierRead, ""},
		{"removing an essential package", "pkg rm web1 openssh-server", tierDangerous, "removes a package the server needs to run or to let you in"},
		{"removing another package", "pkg rm web1 htop", tierChange, "removes the packages"},
		{"a security upgrade", "pkg upgrade web1 --security", tierDangerous, "an update would remove a package the server needs"},
		{"a SQL query", "db query prod DROP TABLE x", tierDangerous, "the SQL deletes data (DROP, DELETE without WHERE, ...)"},
		{"secret rm", "secret rm token", tierDangerous, "deletes the saved passwords"},
		{"group rm asks for a bulk confirm", "group rm big", tierChange, "deleting a group of more than 3 members"},
		{"policy rm", "policy rm deny1", tierSafety, "removes a deny rule"},
		{"a shell is for a person", "shell web1", tierPerson, ""},
		{"a host key reset is for a person", "host trust web1 --reset", tierPerson, "replaces a pinned host key (OD-9)"},
		{"a line that names no command is read, today", "nosuchcommand", tierRead, ""},
	}
	if len(tests) != 20 {
		t.Fatalf("%d lines, want 20", len(tests))
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := riskOfLine(strings.Fields(tt.line))
			note := ""
			for _, s := range []string{r.what, r.dynamic, r.bulk, r.typed} {
				if s != "" {
					note = s
					break
				}
			}
			if r.tier != tt.tier || note != tt.note {
				t.Errorf("riskOfLine(%q) = tier %s, %q; want tier %s, %q", tt.line, r.tier, note, tt.tier, tt.note)
			}
		})
	}
}
