package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// No stop is lost (S-7.1): every gate row TestAgentGolden records has a
// rule-table row at least as high as the stop it shows, read from the
// recording itself, so the table and the commands' own checks cannot
// drift apart.
func TestStandardConfirmTable(t *testing.T) {
	rec, err := os.ReadFile(filepath.Join("testdata", "agent_golden.txt"))
	if err != nil {
		t.Fatal(err)
	}
	head := regexp.MustCompile(`(?m)^### komando -o json (.*) \(agent json, gate inventory\)\nexit (\d+)\n--- stdout\n.*"code":"([A-Z_]+)"`)
	n := 0
	for _, m := range head.FindAllStringSubmatch(string(rec), -1) {
		n++
		var args []string
		for _, g := range goldenGates {
			if strings.Join(g, " ") == m[1] {
				args = g
			}
		}
		if args == nil {
			t.Errorf("no goldenGates line for %q", m[1])
			continue
		}
		r := riskOfLine(args)
		ok := true
		switch code := m[3]; code {
		case "POLICY_BLOCKED":
			ok = r.tier == tierDangerous
		case "PROTECTED_HOST", "PROTECTED_TARGET":
			ok = r.tier >= tierChange
		case "SAFETY_SETTING":
			ok = r.tier == tierSafety
		case "WRITE_REQUIRES_FLAG":
			c, _, _ := newRoot().Find(args)
			k, _ := kindOf(c)
			ok = k.Kind == kindDepends
		case "CONFIRM_REQUIRED":
			ok = r.bulk != ""
		case "NEEDS_PERSON":
			ok = r.tier == tierPerson
		default:
			t.Errorf("%s: no rule for stop %s", m[1], code)
		}
		if !ok {
			t.Errorf("%s stops with %s, but the rule table says %s (%+v)", m[1], m[3], r.tier, r)
		}
	}
	if n != len(goldenGates) {
		t.Errorf("%d recorded gate rows, %d in goldenGates", n, len(goldenGates))
	}
	// every row is consistent: a T3 that holds at once says what goes; a
	// dynamic row says when
	for _, r := range riskRows {
		switch {
		case r.tier == tierDangerous && r.dynamic == "" && r.what == "":
			t.Errorf("%s: a dangerous row says what it does for good", r.id)
		case r.dynamic != "" && r.what != "":
			t.Errorf("%s: a dynamic row has no fixed what", r.id)
		}
	}
}

// A person at a terminal now types the name for the commands that stop an
// AI agent with POLICY_BLOCKED, and still for every one they typed it for
// before (the union, S-7.1).
func TestRiskPersonGains(t *testing.T) {
	for _, line := range []string{
		"reboot web1", "svc stop web1 sshd", "svc disable web1 ssh.service", "sync ./site web1:/var/www --delete",
		"db kill db1 123", "cron rm web1 backup", "secret rm db-pass", "pkg rm web1 nginx",
	} {
		if riskOfLine(strings.Fields(line)).typedWhat() == "" {
			t.Errorf("%s: no typed name", line)
		}
	}
	for _, line := range []string{
		"svc stop web1 nginx", "sync ./site web1:/var/www", "exec web1 -- uptime", "pkg upgrade web1 --security",
		"host edit web1 --port 2222", "group rm web web1",
	} {
		if r := riskOfLine(strings.Fields(line)); r.typedWhat() != "" {
			t.Errorf("%s: typed name %q", line, r.what)
		}
	}
	if r := riskOfLine(strings.Fields("host edit web1 --protected=false")); r.tier != tierSafety {
		t.Errorf("protection off: %s", r.tier)
	}
	if r := riskOfLine(strings.Fields("group rm big")); r.bulk == "" {
		t.Errorf("group rm GROUP: no bulk confirm")
	}
	if r := riskOfLine(strings.Fields("logs web1")); r.tier != tierRead {
		t.Errorf("logs: %s", r.tier)
	}
}

// The schema's confirm comes from the rule table (S-7.7) and matches the
// kind (S-7.8): every runnable command has one, a read's always-tier is
// read and a change's is at least change, every conditional row says when
// in words, and a row that stops agents names the flag that lifts it (none
// for a person-only one).
func TestSchemaConfirm(t *testing.T) {
	for _, r := range riskRows {
		if r.when != nil && r.cond == "" {
			t.Errorf("%s: a row with a condition says it in cond", r.id)
		}
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
		}
		if c.Hidden || !c.Runnable() || !c.HasParent() {
			return
		}
		conf := confirmOf(c)
		k, ok := kindOf(c)
		if !ok {
			return // TestStandard checks every command has a kind
		}
		switch first := conf[0]; {
		case first.When != "":
			t.Errorf("%s: the first confirm holds always: %+v", cmdID(c), first)
		case k.Kind == kindRead && first.Tier != "read" && first.Tier != "person":
			t.Errorf("%s: kind read, confirm %s", cmdID(c), first.Tier)
		case k.Kind != kindRead && first.Tier == "read":
			t.Errorf("%s: kind %s, confirm read", cmdID(c), k.Kind)
		}
		for _, e := range conf {
			if want := map[string]string{"dangerous": "--allow-dangerous", "safety": "--yes", "person": ""}[e.Tier]; (e.Tier == "dangerous" || e.Tier == "safety" || e.Tier == "person") && e.Flag != want {
				t.Errorf("%s: tier %s with flag %q", cmdID(c), e.Tier, e.Flag)
			}
		}
	}
	walk(newRoot())
	d := mustRun(t, "schema", "secret", "rm")
	cmd := d["commands"].([]any)[0].(map[string]any)
	if c, _ := cmd["confirm"].([]any); len(c) != 1 || c[0].(map[string]any)["flag"] != "--allow-dangerous" {
		t.Errorf("schema secret rm: %v", cmd["confirm"])
	}
}
