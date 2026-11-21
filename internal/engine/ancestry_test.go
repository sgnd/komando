package engine

import "testing"

// fakeProcs is a process table for the tests: pid -> process.
type fakeProcs map[int]Proc

func (f fakeProcs) Proc(pid int) (Proc, bool) { p, ok := f[pid]; return p, ok }

func TestAncestorAgent(t *testing.T) {
	agentEnv := env(map[string]string{"CLAUDECODE": "1"})
	for _, c := range []struct {
		name  string
		table fakeProcs
		start int
		want  string
	}{
		{"no agent above", fakeProcs{10: {PPID: 5, Name: "zsh"}, 5: {PPID: 1, Name: "Terminal"}, 1: {Name: "launchd"}}, 10, ""},
		{"the parent holds the variable", fakeProcs{10: {PPID: 1, Name: "sh", Env: agentEnv}}, 10, "Claude Code"},
		{"a grandparent holds it, the shell between was stripped", fakeProcs{
			10: {PPID: 7, Name: "sh", Env: env(nil)}, 7: {PPID: 1, Name: "node", Env: agentEnv}}, 10, "Claude Code"},
		{"known harness name, environment unreadable", fakeProcs{
			10: {PPID: 7, Name: "sh", Env: env(nil)}, 7: {PPID: 1, Name: "claude"}}, 10, "Claude Code"},
		{"known harness name with a path and case", fakeProcs{10: {PPID: 1, Name: "/usr/local/bin/Codex"}}, 10, "Codex"},
		{"an unreadable process does not stop the walk", fakeProcs{
			10: {PPID: 7, Name: "login"}, 7: {PPID: 3, Name: "sh"}, 3: {PPID: 1, Name: "x", Env: agentEnv}}, 10, "Claude Code"},
		{"node harness, argv[1] names it, child env stripped", fakeProcs{
			10: {PPID: 7, Name: "sh", Env: env(nil)},
			7:  {PPID: 1, Name: "node", Args: []string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}}}, 10, "Claude Code"},
		{"argv[0] names it under another process name", fakeProcs{
			10: {PPID: 1, Name: "bun", Args: []string{"/home/a/.local/bin/opencode", "run"}}}, 10, "OpenCode"},
		{"gemini through node", fakeProcs{
			10: {PPID: 1, Name: "node", Args: []string{"node", "/opt/node_modules/@google/gemini-cli/dist/index.js"}}}, 10, "Gemini CLI"},
		{"the script pty wrapper under an agent", fakeProcs{
			10: {PPID: 8, Name: "sh", Env: env(nil)}, 8: {PPID: 7, Name: "script", Env: env(nil)},
			7: {PPID: 1, Name: "claude", Env: env(nil)}}, 10, "Claude Code"},
		{"a person's node script is not an agent", fakeProcs{
			10: {PPID: 1, Name: "node", Args: []string{"node", "/home/a/proj/build.js"}}}, 10, ""},
		{"CLAUDECODE=0 still counts above", fakeProcs{
			10: {PPID: 1, Name: "sh", Env: env(map[string]string{"CLAUDECODE": "0"})}}, 10, "Claude Code"},
		{"a loop ends the walk", fakeProcs{10: {PPID: 11, Name: "a"}, 11: {PPID: 10, Name: "b"}}, 10, ""},
		{"a missing process ends the walk", fakeProcs{10: {PPID: 99, Name: "a"}}, 10, ""},
	} {
		if got := AncestorAgent(c.table, c.start); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAncestorAgentDepthCap(t *testing.T) {
	table := fakeProcs{}
	for i := 10; i < 10+2*maxAncestors; i++ {
		table[i] = Proc{PPID: i + 1, Name: "sh"}
	}
	table[10+2*maxAncestors] = Proc{Name: "claude"}
	if got := AncestorAgent(table, 10); got != "" {
		t.Errorf("a chain longer than the cap: %q", got)
	}
}

// The caller is an agent when only an ancestor shows it: a process that
// stripped its own variables is still an agent's.
func TestCallerSeesAncestorAgent(t *testing.T) {
	c := Call{
		LookupEnv: env(map[string]string{"USER": "ana"}),
		Terminal:  true,
		Ancestors: func() string { return "Claude Code" },
	}
	if got := c.Caller(); !got.IsAgent() || got.Agent != "Claude Code" {
		t.Errorf("%+v", got)
	}
	c.Ancestors = func() string { return "" }
	if got := c.Caller(); got.Kind != Person {
		t.Errorf("no agent above: %+v", got)
	}
	c.Ancestors = nil // an app's call has no process above it
	if got := c.Caller(); got.Kind != Person {
		t.Errorf("nil hook: %+v", got)
	}
}

// The environment still names the agent first (a gate key keeps its name).
func TestCallerEnvironmentWinsOverAncestors(t *testing.T) {
	c := Call{
		LookupEnv: env(map[string]string{GateEnv: "ops-ro"}),
		Ancestors: func() string { return "Claude Code" },
	}
	if got := c.Caller(); got.Agent != "ssh-gate key ops-ro" {
		t.Errorf("%+v", got)
	}
}

func TestParseProcStat(t *testing.T) {
	ppid, name, ok := parseProcStat("812 (my (odd) prog) S 77 812 812 0 -1")
	if !ok || ppid != 77 || name != "my (odd) prog" {
		t.Errorf("%d %q %v", ppid, name, ok)
	}
	for _, bad := range []string{"", "812 no parens", "1 (x) S"} {
		if _, _, ok := parseProcStat(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestProcArgsEnv(t *testing.T) {
	raw := []byte{2, 0, 0, 0}
	raw = append(raw, "/bin/sh\x00\x00\x00sh\x00-c\x00CLAUDECODE=1\x00A=b=c\x00\x00junk"...)
	args, lines := procArgs(raw)
	if len(args) != 2 || args[0] != "sh" || args[1] != "-c" {
		t.Errorf("args %q", args)
	}
	env := envLookup(lines)
	if v, ok := env("CLAUDECODE"); !ok || v != "1" {
		t.Errorf("CLAUDECODE: %q %v", v, ok)
	}
	if v, _ := env("A"); v != "b=c" {
		t.Errorf("A: %q", v)
	}
	if _, ok := env("sh"); ok {
		t.Error("an argument counted as a variable")
	}
	if func() bool { a, e := procArgs([]byte{1}); return a != nil || e != nil }() {
		t.Error("a short buffer")
	}
}
