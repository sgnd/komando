package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each harness's own hook input, from its documentation: a secret read is
// denied in that harness's answer format, an ordinary call is let through.
func TestGuardOtherAgents(t *testing.T) {
	home := "/home/u"
	for _, c := range []struct {
		agent, in string
		deny      bool
	}{
		{"cursor", `{"hook_event_name":"beforeShellExecution","command":"cat ~/.ssh/id_ed25519","cwd":"/p"}`, true},
		{"cursor", `{"hook_event_name":"beforeShellExecution","command":"ls -la","cwd":"/p"}`, false},
		{"cursor", `{"hook_event_name":"beforeReadFile","file_path":"/p/.env","content":"X=1"}`, true},
		{"cursor", `{"hook_event_name":"preToolUse","tool_name":"Write","tool_input":{"file_path":"/home/u/.komando/vault.json"}}`, true},
		{"cursor", `{"hook_event_name":"preToolUse","tool_name":"Grep","tool_input":{"path":"/p/src"}}`, false},
		{"gemini", `{"hook_event_name":"BeforeTool","tool_name":"read_file","tool_input":{"file_path":"/home/u/.ssh/id_ed25519"}}`, true},
		{"gemini", `{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"env","dir_path":"/p"}}`, true},
		{"gemini", `{"hook_event_name":"BeforeTool","tool_name":"glob","tool_input":{"pattern":"**/*.go","path":"/p"}}`, false},
		{"gemini", `{"hook_event_name":"BeforeTool","tool_name":"read_many_files","tool_input":{"paths":["src/a.go","/p/.env"]}}`, true},
		{"codex", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"}}`, true},
		{"codex", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"go test ./..."}}`, false},
		{"codex", `{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: /home/u/.komando/state.json\n@@\n-a\n+b\n*** End Patch"}}`, true},
		{"codex", `{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: src/x.go\n+package x\n*** End Patch"}}`, false},
		{"gemini", `not json`, false},
	} {
		d := guardAgent(c.agent, []byte(c.in), home)
		if d.Deny != c.deny {
			t.Errorf("%s %s: deny %v (%s)", c.agent, c.in, d.Deny, d.Reason)
		}
		ans := guardAnswer(c.agent, d)
		var m map[string]any
		switch {
		case c.agent == "cursor":
			if json.Unmarshal(ans, &m) != nil || m["permission"] != map[bool]string{true: "deny", false: "allow"}[c.deny] {
				t.Errorf("cursor answer %s", ans)
			}
		case !c.deny:
			if ans != nil {
				t.Errorf("%s allow prints %s", c.agent, ans)
			}
		case c.agent == "gemini":
			if json.Unmarshal(ans, &m) != nil || m["decision"] != "deny" || !strings.HasPrefix(m["reason"].(string), "komando guard: ") {
				t.Errorf("gemini answer %s", ans)
			}
		case c.agent == "codex":
			if !strings.Contains(string(ans), `"permissionDecision":"deny"`) {
				t.Errorf("codex answer %s", ans)
			}
		}
	}
}

// guide install sets the guard up for the agents whose folders exist,
// keeps the person's own hooks, and is unchanged when run again.
func TestGuideInstallOtherAgents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KOMANDO_HOME", t.TempDir())
	for _, d := range []string{".cursor", ".gemini", ".codex"} {
		os.MkdirAll(filepath.Join(home, d), 0o755)
	}
	os.WriteFile(filepath.Join(home, ".gemini", "settings.json"), []byte(`{"theme":"dark","hooks":{"BeforeTool":[{"matcher":"x","hooks":[{"type":"command","command":"mine"}]}]}}`), 0o600)
	run := func() {
		root := newRoot()
		root.SetArgs([]string{"-o", "json", "guide", "install"})
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
	}
	run()
	read := func(p string) map[string]any {
		b, err := os.ReadFile(filepath.Join(home, p))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		json.Unmarshal(b, &m)
		return m
	}
	cur := read(".cursor/hooks.json")
	if cur["version"] != float64(1) || !strings.Contains(jsonStr(cur), "guide guard --for cursor") || !strings.Contains(jsonStr(cur), "beforeReadFile") {
		t.Errorf("cursor %s", jsonStr(cur))
	}
	gem := read(".gemini/settings.json")
	if gem["theme"] != "dark" || !strings.Contains(jsonStr(gem), `"mine"`) || !strings.Contains(jsonStr(gem), "guide guard --for gemini") {
		t.Errorf("gemini %s", jsonStr(gem))
	}
	if !strings.Contains(jsonStr(read(".codex/hooks.json")), "guide guard --for codex") {
		t.Error("codex")
	}
	before, _ := os.ReadFile(filepath.Join(home, ".gemini", "settings.json"))
	run()
	after, _ := os.ReadFile(filepath.Join(home, ".gemini", "settings.json"))
	if string(before) != string(after) || strings.Count(string(after), "guide guard") != 1 {
		t.Errorf("a second install changed it:\n%s", after)
	}
}

func jsonStr(v any) string { b, _ := json.Marshal(v); return string(b) }
