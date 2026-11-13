package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// Every command whose Use has COMMAND... or ARGS... after -- takes the
// words for the other program only after --: without -- (or with words
// between the fixed positionals and --) it is a usage error that runs
// nothing, for agents, scripts and people alike (S-4.4).
func TestStandardPassthrough(t *testing.T) {
	invHome(t)
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	var want []string
	for _, c := range allCommands(newRoot(tcl)) {
		if !c.Runnable() || c.Hidden || !strings.Contains(c.Use, "...") {
			continue
		}
		n := passthroughFixed(c.Use)
		if strings.Contains(c.Use, "-- ") || strings.Contains(c.Use, "[--]") {
			if n < 0 {
				t.Errorf("%s: Use %q has -- but is not a passthrough command", c.CommandPath(), c.Use)
				continue
			}
		} else {
			continue
		}
		path := strings.Fields(strings.TrimPrefix(c.CommandPath(), "komando "))
		want = append(want, strings.Join(path, " "))
		fixed := slices.Repeat([]string{"x1"}, n)
		for _, words := range [][]string{
			{"apt-get", "install", "-y", "nginx"}, // -y would be --yes
			{"uptime", "--dry-run"},               // --dry-run would be komando's
			{"stray", "--", "uptime"},             // a word before --
		} {
			args := append(append(slices.Clone(path), fixed...), words...)
			code, s := runMain(t, args...)
			if code != out.ExitUsage || !strings.Contains(s, `"code":"USAGE"`) || !strings.Contains(s, "put -- before the command") {
				t.Errorf("%v: exit %d %s", args, code, s)
			}
		}
	}
	slices.Sort(want)
	all := []string{"cache run", "cluster exec", "cluster run", "cluster shell", "docker compose", "docker exec", "docker raw", "exec", "job start"}
	if !slices.Equal(want, all) {
		t.Errorf("passthrough commands %v, want %v", want, all)
	}
}

// The documented forms keep working: flags before --, -c, --script.
func TestPassthroughDocumentedForms(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	for _, args := range [][]string{
		{"--dry-run", "exec", "web1", "--", "apt-get", "install", "-y", "nginx"},
		{"exec", "web1", "--dry-run", "-P", "2", "--read-only", "--", "df", "-h"},
		{"--dry-run", "exec", "web1", "-c", "uptime"},
		{"--dry-run", "x", "web1", "--", "uptime"},
		{"--dry-run", "job", "start", "web1", "--", "sleep", "1"},
	} {
		mustRun(t, args...)
	}
	// -y given before -- is komando's own; after -- it goes to the server
	d := mustRun(t, "--dry-run", "exec", "web1", "--", "yum", "update", "-y")
	if !strings.Contains(stringOf(d), "yum update -y") {
		t.Errorf("plan: %v", d)
	}
}

// The USAGE hint never hands out an approval flag: an example with --yes,
// -y, --allow-dangerous or --reveal is skipped (review F10).
func TestDashExampleSkipsApprovalFlags(t *testing.T) {
	c := &cobra.Command{Use: "exec TARGET -- COMMAND", Example: "  komando exec web1 --allow-dangerous -- rm -rf /tmp/x\n" +
		"  komando exec web1 -y -- reboot\n  komando exec web1 -- uptime   # how long it is up"}
	if got := dashExample(c); got != "komando exec web1 -- uptime" {
		t.Errorf("dashExample: %q", got)
	}
	c.Example = "  komando exec web1 -- apt-get install -y nginx" // the other program's -y
	if got := dashExample(c); got != "komando exec web1 -- apt-get install -y nginx" {
		t.Errorf("dashExample: %q", got)
	}
	c.Example = "  komando exec web1 --yes -- touch /tmp/x"
	if got, _, _ := strings.Cut(dashExample(c), " -- "); approvalFlag.MatchString(got) {
		t.Errorf("dashExample with only approval examples: %q", got)
	}
}
