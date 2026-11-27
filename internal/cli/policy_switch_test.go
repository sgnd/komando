package cli

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/store"
)

// A rule a person switched off stops nothing on the servers the switch
// names (by record ID), and still stops a command that also runs anywhere
// else.
func TestPolicyHitsRuleOff(t *testing.T) {
	a := &store.Host{Name: "a", Groups: []string{"web"}, Rec: store.Rec{ID: "id-a"}}
	b := &store.Host{Name: "b", Rec: store.Rec{ID: "id-b"}}
	renamed := &store.Host{Name: "a2", Rec: store.Rec{ID: "id-a"}}
	ids := func(rs []policy.Rule) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return out
	}
	onA := []store.RuleOff{{Rule: "docker-prune", HostIDs: []string{"id-a"}, Groups: []string{"web"}}}
	cases := []struct {
		name  string
		off   []store.RuleOff
		hosts []*store.Host
		cmd   string
		own   bool
		want  bool // the rule still stops it
	}{
		{"no switch", nil, []*store.Host{a}, "docker system prune -f", false, true},
		{"off everywhere", []store.RuleOff{{Rule: "docker-prune", Everywhere: true}}, []*store.Host{a, b}, "docker system prune -f", false, false},
		{"off everywhere, no server", []store.RuleOff{{Rule: "docker-prune", Everywhere: true}}, nil, "docker system prune -f", false, false},
		{"off on a", onA, []*store.Host{a}, "docker system prune -f", false, false},
		{"off on a, a renamed", onA, []*store.Host{renamed}, "docker system prune -f", false, false},
		{"off on a, runs on a and b", onA, []*store.Host{a, b}, "docker system prune -f", false, true},
		{"off on a, no server", onA, nil, "docker system prune -f", false, true},
		{"the group is a label: b joined web later", onA, []*store.Host{{Name: "b", Groups: []string{"web"}, Rec: store.Rec{ID: "id-b"}}}, "docker system prune -f", false, true},
		{"a switch left with no server is not everywhere", []store.RuleOff{{Rule: "docker-prune"}}, []*store.Host{a}, "docker system prune -f", false, true},
		{"another rule off", []store.RuleOff{{Rule: "rm-root", Everywhere: true}}, []*store.Host{a}, "docker system prune -f", false, true},
		{"own script, off", []store.RuleOff{{Rule: "rm-root", Everywhere: true}}, []*store.Host{a}, "rm -rf /", true, false},
		{"own script, on", nil, []*store.Host{a}, "rm -rf /", true, true},
	}
	for _, c := range cases {
		st := &store.State{}
		st.Settings.RulesOff = c.off
		rule := "docker-prune"
		if c.own {
			rule = "rm-root"
		}
		check := policy.Check
		if c.own {
			check = policy.CheckScript
		}
		got := slices.Contains(ids(withoutRulesOff(st, c.hosts, check(c.cmd, nil))), rule)
		if got != c.want {
			t.Errorf("%s: %s stops it = %v, want %v", c.name, rule, got, c.want)
		}
	}
}

// policy edit --off asks first and writes an audit record with the scope
// before and after; --on undoes it; show, list and check read it.
func TestPolicyOffOnShow(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "deploy@10.0.0.1", "--group", "web")
	mustRun(t, "host", "ssh", "add", "db1", "deploy@10.0.0.2")
	wantCode(t, "USAGE", "policy", "edit", "docker-prune")
	wantCode(t, "USAGE", "policy", "edit", "docker-prune", "--off", "--rm-server", "web1", "--yes")
	wantCode(t, "RULE_NOT_FOUND", "policy", "edit", "--off", "nonexistent", "--yes")
	wantCode(t, "TARGET_NOT_FOUND", "policy", "edit", "--off", "docker-prune", "--add-server", "nope", "--yes")
	wantCode(t, "GROUP_NOT_FOUND", "policy", "edit", "--off", "docker-prune", "--add-group", "nope", "--yes")
	wantCode(t, "SAFETY_SETTING", "policy", "edit", "--off", "docker-prune", "--add-server", "web1")

	off := mustRun(t, "policy", "edit", "--off", "docker-prune", "--add-server", "WEB1", "--yes")
	if off["off"] != true || off["everywhere"] != false || fmt.Sprint(off["hosts"]) != "[web1]" {
		t.Errorf("policy edit --off --host: %v", off)
	}
	mustRun(t, "policy", "edit", "--off", "docker-prune", "--add-group", "@web", "--yes")
	show := mustRun(t, "policy", "show", "docker-prune")
	sw := show["switch"].(map[string]any)
	if show["kind"] != "built-in" || fmt.Sprint(sw["hosts"], sw["groups"]) != "[web1] [web]" {
		t.Errorf("policy show after two switches: %v", show)
	}
	a := mustRun(t, "audit", "--command", "policy.edit")
	if a["count"].(float64) != 2 {
		t.Errorf("policy edit is audited as policy.edit: %v", a)
	}
	if b := jsonText(a); !strings.Contains(b, `"before"`) || !strings.Contains(b, `"after"`) || !strings.Contains(b, `"web1"`) {
		t.Errorf("the audit record has no scope before and after: %s", b)
	}
	for _, r := range mustRun(t, "policy", "list")["builtin"].([]any) {
		if m := r.(map[string]any); m["id"] == "docker-prune" && m["off"] != "web1 (from @web)" {
			t.Errorf("policy list: %v", m)
		}
	}
	d, e := invRun(t, "policy", "check", "docker system prune -f")
	if e == nil || e.Code != "POLICY_BLOCKED" || fmt.Sprint(d["off"]) != "map[docker-prune:web1 (from @web)]" {
		t.Errorf("policy check does not say where the rule is off: %v %+v", d, e)
	}

	mustRun(t, "policy", "edit", "docker-prune", "--rm-server", "web1")
	if sw := mustRun(t, "policy", "show", "docker-prune")["switch"].(map[string]any); sw["off"] != false {
		t.Errorf("on for every server it named takes the switch away, not off everywhere: %v", sw)
	}
	mustRun(t, "policy", "edit", "--off", "docker-prune", "--yes")
	wantCode(t, "USAGE", "policy", "edit", "docker-prune", "--rm-server", "web1")
	mustRun(t, "policy", "edit", "docker-prune", "--off=false")
	if sw := mustRun(t, "policy", "show", "docker-prune")["switch"].(map[string]any); sw["off"] != false {
		t.Errorf("policy edit --off=false: %v", sw)
	}
	mustRun(t, "policy", "deny", `kubectl\s+apply`)
	custom := policy.CustomID(`kubectl\s+apply`)
	mustRun(t, "policy", "edit", "--off", custom, "--add-server", "db1", "--yes")
	if show := mustRun(t, "policy", "show", custom); show["kind"] != "custom" || fmt.Sprint(show["switch"].(map[string]any)["hosts"]) != "[db1]" {
		t.Errorf("a custom rule switched off: %v", show)
	}
	wantCode(t, "RULE_NOT_FOUND", "policy", "show", "nonexistent")
}

// An AI agent may ask for a rule to go off: the approval window opens on
// the person's screen, and nobody answering is a no, in every spelling of
// the flag. --on makes a check stricter and needs no window.
func TestPolicyEditOffAsksThePerson(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "deploy@10.0.0.1")
	shown := asAgent(t, false, true)
	for _, args := range [][]string{
		{"policy", "edit", "docker-prune", "--off", "--yes"},
		{"policy", "edit", "--off", "docker-prune", "--yes"},
		{"policy", "edit", "docker-prune", "--off=true", "--yes"},
		{"policy", "edit", "docker-prune", "--off=false", "--off", "--yes"},
	} {
		before := *shown
		if _, e := invRun(t, args...); e == nil || e.Code != "SAFETY_SETTING" || *shown == before {
			t.Errorf("agent %v: want the window and SAFETY_SETTING, got %+v (windows %d)", args, e, *shown-before)
		}
	}
	if sw := mustRun(t, "policy", "show", "docker-prune")["switch"].(map[string]any); sw["off"] != false {
		t.Errorf("a rule went off with no one's yes: %v", sw)
	}
	// a keystone rule is never the window's: the person runs it at a terminal
	before := *shown
	if _, e := invRun(t, "policy", "edit", "rm-root", "--off", "--add-server", "web1", "--yes"); e == nil || e.Code != "NEEDS_PERSON" ||
		!strings.Contains(e.Hint, "`komando policy edit rm-root --off --add-server web1`") || *shown != before {
		t.Errorf("agent, keystone rule: want NEEDS_PERSON naming the command and no window, got %+v (windows %d)", e, *shown-before)
	}
	mustRun(t, "policy", "edit", "docker-prune", "--off=false")
	asAgent(t, true, true)
	if sw := mustRun(t, "policy", "edit", "docker-prune", "--off", "--yes"); sw["off"] != true {
		t.Errorf("the person allowed it in the window: %v", sw)
	}
	wantCode(t, "NEEDS_PERSON", "policy", "edit", "decode-run", "--off", "--yes")
}

// A keystone rule takes a typed name: a script with no terminal is refused
// even with --yes, and a dry run only reports.
func TestPolicyEditKeystoneNeedsATerminal(t *testing.T) {
	invHome(t)
	e := wantCode(t, "SAFETY_SETTING", "policy", "edit", "rm-root", "--off", "--yes")
	if !strings.Contains(e.Hint, "run it in a terminal") {
		t.Errorf("hint: %q", e.Hint)
	}
	if _, e := invRun(t, "policy", "edit", "rm-root", "--off", "--dry-run"); e != nil {
		t.Errorf("a dry run reports: %+v", e)
	}
	if sw := mustRun(t, "policy", "show", "rm-root")["switch"].(map[string]any); sw["off"] != false {
		t.Errorf("a keystone rule went off with no typed name: %v", sw)
	}
	mustRun(t, "policy", "edit", "docker-prune", "--off", "--yes") // any other rule: --yes is the person's yes
}

// The keystone list is a decision: every rule for the root folder, a
// device, a Windows hive or a way to hide what runs is in it, and each
// entry is a rule that exists.
func TestKeystoneRules(t *testing.T) {
	want := []string{"check-failed", "base64-pipe-sh", "decode-run", "curl-pipe-sh", "win-encoded", "win-decode-run", "win-download-run",
		"rm-root", "rm-cd-root", "find-delete-root", "rm-system-dir", "chmod-root", "chown-root", "mkfs", "dd-device", "redirect-device", "wipefs",
		"win-rm-root", "win-format", "win-registry-hive", "win-backups", "passwd-files", "passwd-files-write", "docker-host",
		"sshd-stop", "win-remote-access", "firewall-drop-all"}
	if !slices.Equal(keystoneRules, want) {
		t.Errorf("keystoneRules = %v, want %v", keystoneRules, want)
	}
	ids := map[string]bool{}
	for _, r := range policy.Rules() {
		ids[r.ID] = true
		if strings.Contains(r.ID, "root") || strings.Contains(r.ID, "device") || strings.Contains(r.ID, "hive") ||
			strings.Contains(r.ID, "decode") || strings.Contains(r.ID, "pipe-sh") || strings.Contains(r.ID, "encoded") || strings.Contains(r.ID, "download") {
			if !slices.Contains(keystoneRules, r.ID) {
				t.Errorf("%s looks like a rule that keeps the others working: decide whether it is a keystone rule", r.ID)
			}
		}
	}
	for _, id := range keystoneRules {
		if !ids[id] {
			t.Errorf("keystone rule %s is not a rule", id)
		}
	}
}

// The switch reaches the check every exec line goes through: a rule off on
// one server lets that server's line through and still stops a line that
// also runs on another, on a server added to the group later, and on a
// server of the same name made again.
func TestPolicyEditOffReachesExec(t *testing.T) {
	invHome(t)
	addr := "deploy@" + closedAddr(t)
	mustRun(t, "host", "ssh", "add", "web1", addr, "--group", "lab")
	mustRun(t, "host", "ssh", "add", "db1", addr)
	line := []string{"--", "docker system prune -f"}
	wantCode(t, "POLICY_BLOCKED", append([]string{"host", "ssh", "exec", "web1"}, line...)...)
	mustRun(t, "policy", "edit", "docker-prune", "--off", "--add-group", "lab", "--yes")
	// past the policy the line goes to the server, which is not there
	if _, e := invRun(t, append([]string{"host", "ssh", "exec", "web1"}, line...)...); e == nil || e.Code == "POLICY_BLOCKED" {
		t.Errorf("off on @lab: want the connection error, got %+v", e)
	}
	wantCode(t, "POLICY_BLOCKED", append([]string{"host", "ssh", "exec", "web1,db1"}, line...)...)
	wantCode(t, "POLICY_BLOCKED", "host", "ssh", "exec", "web1", "--", "rm -rf /")
	mustRun(t, "host", "ssh", "add", "web9", addr, "--group", "lab")
	wantCode(t, "POLICY_BLOCKED", append([]string{"host", "ssh", "exec", "web9"}, line...)...)
	mustRun(t, "host", "ssh", "remove", "web1", "--yes")
	mustRun(t, "host", "ssh", "add", "web1", addr)
	wantCode(t, "POLICY_BLOCKED", append([]string{"host", "ssh", "exec", "web1"}, line...)...)
	if sw := mustRun(t, "policy", "show", "docker-prune")["switch"].(map[string]any); sw["off"] != false {
		t.Errorf("a removed server is still in the switch: %v", sw)
	}
}

// doctor warns for every rule that is off, the keystone rules first.
func TestDoctorNamesRulesOff(t *testing.T) {
	setHome(t, t.TempDir())
	st := &store.State{Conns: map[string]*store.Conn{}, Hosts: map[string]*store.Host{}, Vpns: map[string]*store.Vpn{}}
	st.Settings.RulesOff = []store.RuleOff{{Rule: "docker-prune", Everywhere: true}, {Rule: "decode-run", Everywhere: true}}
	var got []string
	for _, c := range securityChecks(tcl, st) {
		if strings.HasPrefix(c.Name, "security:rule_off:") && c.Warning {
			got = append(got, strings.TrimPrefix(c.Name, "security:rule_off:"))
		}
	}
	if fmt.Sprint(got) != "[decode-run docker-prune]" {
		t.Errorf("doctor warns for %v, want the keystone rule first: [decode-run docker-prune]", got)
	}
}

// At a terminal, a keystone rule goes off only when the person types its
// name, --yes or not; a carried rule takes a plain yes.
func TestPolicyEditOffAtATerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	unixOnly(t, "drives a terminal")
	invHome(t)
	p := startPTYEnv(t, []string{"KOMANDO_PTY_AS=person"}, "policy", "edit", "rm-root", "--off")
	p.answer("Type the name rm-root", "y\r")
	if code := p.exit(); code != out.ExitPolicy || !strings.Contains(p.shown(), "with this off, komando no longer catches") {
		t.Errorf("a plain yes for a keystone rule: exit %d\n%s", code, p.shown())
	}
	p = startPTYEnv(t, []string{"KOMANDO_PTY_AS=person"}, "policy", "edit", "rm-root", "--off")
	p.answer("Type the name rm-root", "rm-root\r")
	if code := p.exit(); code != 0 {
		t.Errorf("the typed name: exit %d\n%s", code, p.shown())
	}
	p = startPTYEnv(t, []string{"KOMANDO_PTY_AS=person"}, "policy", "edit", "rm-root", "--off", "--yes")
	p.answer("Type the name rm-root", "y\r")
	if code := p.exit(); code != out.ExitPolicy {
		t.Errorf("--yes in place of the typed name: exit %d\n%s", code, p.shown())
	}
	p = startPTYEnv(t, []string{"KOMANDO_PTY_AS=person"}, "policy", "edit", "docker-prune", "--off")
	p.answer("[y/N]", "y\r")
	if code := p.exit(); code != 0 || !strings.Contains(p.shown(), "komando no longer stops a command that") {
		t.Errorf("a plain yes for a carried rule: exit %d\n%s", code, p.shown())
	}
}

// The v2.7 table rates policy edit by flags only (internal/capability); for
// every line it must be at least as strict as today's switchesOn.
func TestPolicyEditTableNotWeaker(t *testing.T) {
	key := capability.Key{Type: "policy", Verb: "edit"}
	tableTier := func(words []string) capability.Tier {
		best := capability.Change
		for _, r := range capability.TierRows() {
			if !r.Reaches(key) || r.Tier <= best {
				continue
			}
			met := true
			for _, f := range r.When.Flags {
				met = met && slices.ContainsFunc(words, func(w string) bool { return w == "--"+f || strings.HasPrefix(w, "--"+f+"=") })
			}
			if met {
				best = r.Tier
			}
		}
		return best
	}
	for _, line := range []string{
		"policy edit r --off", "policy edit r --off=true", "policy edit r --off=false", "policy edit r --off=false --off",
		"policy edit r --rm-server web1", "policy edit r --rm-group lab", "policy edit r --add-server web1",
		"policy edit r --add-group lab", "policy edit r --off --add-server web1", "policy edit r --off=false --off --bogus",
	} {
		_, words, _ := lineWords(strings.Fields(line))
		if today, table := riskOfLine(strings.Fields(line)).tier, tableTier(words); int(table) < int(today) {
			t.Errorf("%s: the v2.7 table gives tier %d, today's rows %d", line, table, today)
		}
	}
}

// --rm-group takes a group the switch names even when the group has no
// servers any more, so its label goes; the servers the group had when the
// rule went off stay in the switch until they are taken out by name.
func TestPolicyEditRmGroupDropsEmptyLabel(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "deploy@10.0.0.1", "--group", "lab")
	mustRun(t, "policy", "edit", "docker-prune", "--off", "--add-group", "lab", "--yes")
	mustRun(t, "host", "ssh", "edit", "web1", "--rm-group", "lab")
	wantCode(t, "GROUP_NOT_FOUND", "policy", "edit", "docker-prune", "--rm-group", "nope")
	sw := mustRun(t, "policy", "edit", "docker-prune", "--rm-group", "lab")
	if fmt.Sprint(sw["groups"], sw["hosts"]) != "[] [web1]" {
		t.Errorf("--rm-group of an emptied group: want the label gone and web1 kept, got %v", sw)
	}
	mustRun(t, "policy", "edit", "docker-prune", "--rm-server", "web1")
	if sw := mustRun(t, "policy", "show", "docker-prune")["switch"].(map[string]any); sw["off"] != false {
		t.Errorf("the switch named nothing more: %v", sw)
	}
}
