package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
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
		stopHasRow(t, args, m[3])
	}
	if n != len(goldenGates) {
		t.Errorf("%d recorded gate rows, %d in goldenGates", n, len(goldenGates))
	}
	// the stops only an AI agent meets, which the recording (made without
	// an agent's window, in one shared home) cannot show: each still stops
	// as written here, and has its row
	for _, c := range agentStops {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			invHome(t)
			noAgent(t)
			if c.setup != nil {
				c.setup(t)
			}
			asAgent(t, false, false) // no window: nobody says yes
			d, e := invRun(t, c.args...)
			if c.code == "" { // the command leaves the item out instead of stopping
				if e != nil && e.Code != "IMPORT_INCOMPLETE" || !strings.Contains(fmt.Sprint(d["skipped"]), c.skipped) {
					t.Fatalf("want it left out (%q), got %v %+v", c.skipped, d, e)
				}
				stopHasRow(t, c.args, "SAFETY_SETTING")
				return
			}
			if e == nil || e.Code != c.code {
				t.Fatalf("want %s, got %v %+v", c.code, d, e)
			}
			stopHasRow(t, c.args, c.code)
		})
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

// stopHasRow fails unless the rule table has a row for the stop code that
// line meets: a row of that tier applies to the line, and any higher row
// that applies is one the command decides at run time (dynamic), so
// `komando schema` names the stop an agent plans for.
func stopHasRow(t *testing.T, line []string, code string) {
	t.Helper()
	c, words, _ := lineWords(line)
	if c == nil {
		t.Errorf("%v: no command", line)
		return
	}
	var rows []riskRow
	for _, r := range riskRows {
		if r.id == cmdID(c) && (r.when == nil || r.when(words)) {
			rows = append(rows, r)
		}
	}
	has := func(tr tier) bool {
		for _, r := range rows {
			if r.tier > tr && r.dynamic == "" {
				return false // a fixed higher row would hide it
			}
		}
		return slices.ContainsFunc(rows, func(r riskRow) bool { return r.tier == tr })
	}
	best := riskOf(c, words)
	ok := true
	switch code {
	case "POLICY_BLOCKED":
		ok = has(tierDangerous)
	case "PROTECTED_HOST", "PROTECTED_TARGET":
		ok = best.tier >= tierChange
	case "SAFETY_SETTING":
		ok = has(tierSafety)
	case "WRITE_REQUIRES_FLAG":
		k, _ := kindOf(c)
		ok = k.Kind == kindDepends
	case "CONFIRM_REQUIRED":
		ok = best.bulk != ""
	case "NEEDS_PERSON":
		ok = has(tierPerson)
	default:
		t.Errorf("%v: no rule for stop %s", line, code)
	}
	if !ok {
		t.Errorf("%v stops with %s, but the rule table has no such row for it (rows %+v)", line, code, rows)
	}
}

// agentStop is a stop only an AI agent meets: setup runs as a script,
// args as an agent whose window nobody answers. code is the stop; an empty
// code means the command leaves the item out, saying skipped.
type agentStop struct {
	args          []string
	setup         func(t *testing.T)
	code, skipped string
}

var agentStops = []agentStop{
	{args: []string{"host", "ssh-command", "web1"}, code: "NEEDS_PERSON",
		setup: func(t *testing.T) { mustRun(t, "host", "add", "web1", "deploy@10.0.0.1") }},
	{args: []string{"secret", "keychain"}, code: "NEEDS_PERSON"},
	{args: []string{"host", "add", "px", "u@10.0.0.1", "--proxy-command", "nc %h %p"}, code: "SAFETY_SETTING"},
	{args: []string{"host", "edit", "web1", "--proxy-command", "nc %h %p"}, code: "SAFETY_SETTING",
		setup: func(t *testing.T) { mustRun(t, "host", "add", "web1", "deploy@10.0.0.1") }},
	{args: []string{"import", "ssh-config", "testdata/risk_proxy_ssh_config"}, skipped: "--yes"},
	{args: []string{"import", "kubeconfig", "testdata/risk_exec_kubeconfig"}, code: "SAFETY_SETTING"},
	{args: []string{"recipe", "add", "free-space", "df -h", "--overwrite", "--read-only"}, code: "SAFETY_SETTING",
		setup: func(t *testing.T) { mustRun(t, "recipe", "add", "free-space", "df -h") }},
	{args: []string{"host", "trust", "web1"}, code: "SAFETY_SETTING", setup: func(t *testing.T) {
		key := new(atomic.Pointer[ssh.Signer])
		s := trustSigner(t)
		key.Store(&s)
		mustRun(t, "host", "add", "web1", "root@127.0.0.1:"+strconv.Itoa(keySSHD(t, key)))
		mustRun(t, "config", "set", "host_key_policy", "strict")
	}},
	{args: []string{"guide", "uninstall"}, code: "SAFETY_SETTING", setup: func(t *testing.T) {
		fakeHome := t.TempDir()
		t.Setenv("HOME", fakeHome)
		t.Setenv("USERPROFILE", fakeHome) // os.UserHomeDir reads USERPROFILE on Windows
		mustRun(t, "guide", "install")
	}},
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
