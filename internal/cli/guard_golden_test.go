package cli

import (
	"fmt"
	"strings"
	"testing"
)

// TestGuardGolden pins what `komando guide guard`, the hidden hook an agent
// harness runs before every tool call, answers for a few calls: let
// through (it prints nothing), denied, and input it cannot read (let
// through). The guard has no third answer today.
func TestGuardGolden(t *testing.T) {
	if testing.Short() || raceOn {
		t.Skip("runs the guard as a hook")
	}
	unixOnly(t, "the recording is made on Unix: home paths differ on Windows")
	var b strings.Builder
	for _, c := range []struct{ name, args, in string }{
		{"allow: an ordinary command", "", `{"tool_name":"Bash","tool_input":{"command":"go test ./..."},"cwd":"/p"}`},
		{"allow: a komando command", "", `{"tool_name":"Bash","tool_input":{"command":"komando exec web1 --read-only -- uptime"},"cwd":"/p"}`},
		{"deny: reading a private key", "", `{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_ed25519"},"cwd":"/p"}`},
		{"deny: reading a .env file", "", `{"tool_name":"Read","tool_input":{"file_path":"/p/.env"},"cwd":"/p"}`},
		{"unreadable input", "", `not json`},
		{"deny, codex format", "--for codex", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat .env"}}`},
		{"allow, cursor format", "--for cursor", `{"hook_event_name":"beforeShellExecution","command":"ls -la","cwd":"/p"}`},
	} {
		args := append([]string{"guide", "guard"}, strings.Fields(c.args)...)
		stdout, stderr, code := goldenRunIn(t, true, args, nil, c.in)
		fmt.Fprintf(&b, "### %s\nkomando %s < %s\nexit %d\n--- stdout\n%s--- stderr\n%s", c.name, strings.Join(args, " "), c.in, code, stdout, stderr)
	}
	matchGolden(t, "testdata/guard_golden.txt", b.String())
}

// A tool call larger than the guard reads whole is refused in every
// harness's format, here a 5 MiB write to komando's own folder.
func TestGuardRefusesOversizedCall(t *testing.T) {
	content := strings.Repeat("x", 5<<20)
	write := `"tool_input":{"file_path":"~/.komando/x","content":"` + content + `"}`
	for _, c := range []struct{ args, in string }{
		{"", `{"tool_name":"Write",` + write + `,"cwd":"/p"}`},
		{"--for codex", `{"hook_event_name":"PreToolUse","tool_name":"Write",` + write + `}`},
		{"--for cursor", `{"hook_event_name":"preToolUse","tool_name":"Write",` + write + `,"cwd":"/p"}`},
		{"--for gemini", `{"hook_event_name":"BeforeTool","tool_name":"write_file",` + write + `}`},
	} {
		args := append([]string{"guide", "guard"}, strings.Fields(c.args)...)
		stdout, _, _ := goldenRunIn(t, true, args, nil, c.in)
		if !strings.Contains(stdout, "deny") || !strings.Contains(stdout, "too large for komando's guard to check") {
			t.Errorf("%q: want a denial for a call over 4 MiB, got %.200q", c.args, stdout)
		}
	}
}
