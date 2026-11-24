package cli

import (
	"fmt"
	"slices"
	"testing"

	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/store"
)

// A built-in rule a person switched off stops nothing on the servers the
// switch names, and still stops a command that also runs anywhere else.
func TestPolicyHitsRuleOff(t *testing.T) {
	a := &store.Host{Name: "a", Groups: []string{"web"}}
	b := &store.Host{Name: "b"}
	ids := func(rs []policy.Rule) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return out
	}
	cases := []struct {
		name  string
		off   []store.RuleOff
		hosts []*store.Host
		cmd   string
		own   bool
		want  bool // the rule still stops it
	}{
		{"no switch", nil, []*store.Host{a}, "docker system prune -f", false, true},
		{"off everywhere", []store.RuleOff{{Rule: "docker-prune"}}, []*store.Host{a, b}, "docker system prune -f", false, false},
		{"off everywhere, no server", []store.RuleOff{{Rule: "docker-prune"}}, nil, "docker system prune -f", false, false},
		{"off on a", []store.RuleOff{{Rule: "docker-prune", Hosts: []string{"a"}}}, []*store.Host{a}, "docker system prune -f", false, false},
		{"off on a, name in other case", []store.RuleOff{{Rule: "docker-prune", Hosts: []string{"A"}}}, []*store.Host{a}, "docker system prune -f", false, false},
		{"off on a, runs on a and b", []store.RuleOff{{Rule: "docker-prune", Hosts: []string{"a"}}}, []*store.Host{a, b}, "docker system prune -f", false, true},
		{"off on a, no server", []store.RuleOff{{Rule: "docker-prune", Hosts: []string{"a"}}}, nil, "docker system prune -f", false, true},
		{"off on group web", []store.RuleOff{{Rule: "docker-prune", Groups: []string{"web"}}}, []*store.Host{a}, "docker system prune -f", false, false},
		{"off on group web, b not in it", []store.RuleOff{{Rule: "docker-prune", Groups: []string{"web"}}}, []*store.Host{b}, "docker system prune -f", false, true},
		{"another rule off", []store.RuleOff{{Rule: "rm-root"}}, []*store.Host{a}, "docker system prune -f", false, true},
		{"own script, off", []store.RuleOff{{Rule: "rm-root"}}, []*store.Host{a}, "rm -rf /", true, false},
		{"own script, on", nil, []*store.Host{a}, "rm -rf /", true, true},
	}
	for _, c := range cases {
		st := &store.State{}
		st.Settings.RulesOff = c.off
		rule := "docker-prune"
		if c.own {
			rule = "rm-root"
		}
		got := slices.Contains(ids(policyHits(st, c.hosts, c.cmd, c.own)), rule)
		if got != c.want {
			t.Errorf("%s: %s stops it = %v, want %v", c.name, rule, got, c.want)
		}
	}
}

// policy edit --off asks a person first and writes an audit record;
// --on undoes it and show reads it; only built-in rules can be switched.
func TestPolicyOffOnShow(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1", "--group", "web")
	mustRun(t, "host", "add", "db1", "deploy@10.0.0.2")
	wantCode(t, "USAGE", "policy", "edit", "docker-prune")
	wantCode(t, "USAGE", "policy", "edit", "docker-prune", "--off", "--on", "--yes")
	wantCode(t, "RULE_NOT_FOUND", "policy", "edit", "--off", "nonexistent", "--yes")
	mustRun(t, "policy", "deny", `kubectl\s+apply`)
	wantCode(t, "RULE_NOT_FOUND", "policy", "edit", "--off", policy.CustomID(`kubectl\s+apply`), "--yes")
	wantCode(t, "TARGET_NOT_FOUND", "policy", "edit", "--off", "docker-prune", "--host", "nope", "--yes")
	wantCode(t, "GROUP_NOT_FOUND", "policy", "edit", "--off", "docker-prune", "--group", "nope", "--yes")
	wantCode(t, "SAFETY_SETTING", "policy", "edit", "--off", "docker-prune", "--host", "web1")

	off := mustRun(t, "policy", "edit", "--off", "docker-prune", "--host", "WEB1", "--yes")
	if off["off"] != true || off["everywhere"] != false || fmt.Sprint(off["hosts"]) != "[web1]" {
		t.Errorf("policy off --host: %v", off)
	}
	mustRun(t, "policy", "edit", "--off", "docker-prune", "--group", "@web", "--yes")
	show := mustRun(t, "policy", "show", "docker-prune")
	sw := show["switch"].(map[string]any)
	if show["kind"] != "built-in" || fmt.Sprint(sw["hosts"], sw["groups"]) != "[web1] [web]" {
		t.Errorf("policy show after two switches: %v", show)
	}
	if a := mustRun(t, "audit", "--command", "policy.edit"); a["count"].(float64) != 2 {
		t.Errorf("policy edit is audited as policy.edit: %v", a)
	}
	for _, r := range mustRun(t, "policy", "list")["builtin"].([]any) {
		if m := r.(map[string]any); m["id"] == "docker-prune" && m["off"] != "web1, @web" {
			t.Errorf("policy list: %v", m)
		}
	}

	mustRun(t, "policy", "edit", "--on", "docker-prune", "--host", "web1")
	mustRun(t, "policy", "edit", "--on", "docker-prune", "--group", "web")
	if sw := mustRun(t, "policy", "show", "docker-prune")["switch"].(map[string]any); sw["off"] != false {
		t.Errorf("on for every server it named takes the switch away, not off everywhere: %v", sw)
	}
	mustRun(t, "policy", "edit", "--off", "docker-prune", "--yes")
	wantCode(t, "USAGE", "policy", "edit", "--on", "docker-prune", "--host", "web1")
	mustRun(t, "policy", "edit", "--on", "docker-prune")
	if sw := mustRun(t, "policy", "show", "docker-prune")["switch"].(map[string]any); sw["off"] != false {
		t.Errorf("policy on: %v", sw)
	}
	if show := mustRun(t, "policy", "show", policy.CustomID(`kubectl\s+apply`)); show["kind"] != "custom" {
		t.Errorf("policy show of a custom rule: %v", show)
	}
	wantCode(t, "RULE_NOT_FOUND", "policy", "show", "nonexistent")
}

// Switching a rule off is a person's choice: an AI agent's policy edit
// without --on is refused when the person says no in the window, in every
// spelling of the flag; --on makes a check stricter and needs no one.
func TestPolicyEditOffNeedsPerson(t *testing.T) {
	invHome(t)
	asAgent(t, false, true)
	for _, args := range [][]string{
		{"policy", "edit", "docker-prune", "--off", "--yes"},
		{"policy", "edit", "--off", "docker-prune", "--yes"},
		{"policy", "edit", "docker-prune", "--off=true", "--yes"},
		{"policy", "edit", "docker-prune", "--off", "--host", "web1", "--yes"},
	} {
		if _, e := invRun(t, args...); e == nil || (e.Code != "SAFETY_SETTING" && e.Code != "TARGET_NOT_FOUND") {
			t.Errorf("agent %v: want SAFETY_SETTING, got %+v", args, e)
		}
	}
	if sw := mustRun(t, "policy", "show", "docker-prune")["switch"].(map[string]any); sw["off"] != false {
		t.Errorf("an agent switched a rule off: %v", sw)
	}
	mustRun(t, "policy", "edit", "docker-prune", "--on")
}

// The switch reaches the check every exec line goes through: a rule off on
// one server lets that server's line through and still stops a line that
// also runs on another.
func TestPolicyEditOffReachesExec(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "deploy@"+closedAddr(t))
	mustRun(t, "host", "add", "db1", "deploy@"+closedAddr(t))
	line := []string{"--", "docker system prune -f"}
	wantCode(t, "POLICY_BLOCKED", append([]string{"exec", "web1", "--dry-run"}, line...)...)
	mustRun(t, "policy", "edit", "docker-prune", "--off", "--host", "web1", "--yes")
	if _, e := invRun(t, append([]string{"exec", "web1", "--dry-run"}, line...)...); e != nil {
		t.Errorf("off on web1: want the dry run, got %+v", e)
	}
	wantCode(t, "POLICY_BLOCKED", append([]string{"exec", "web1,db1", "--dry-run"}, line...)...)
	wantCode(t, "POLICY_BLOCKED", "exec", "web1", "--dry-run", "--", "rm -rf /")
}
