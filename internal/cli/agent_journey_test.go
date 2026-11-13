package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// The approval hint tells an agent that adding the flag asks the user only
// where a flag opens the window.
func TestApprovalHintOnlyWhereAFlagAsks(t *testing.T) {
	asAgent(t, false, true)
	for _, tc := range []struct {
		e          *out.Error
		want, nope string
	}{
		{&out.Error{Code: "POLICY_BLOCKED", Hint: "check it", Exit: out.ExitPolicy}, "komando then asks them in a window", ""},
		{(&out.Error{Code: "UNSAFE_BACKUP", Hint: "fix that line", Exit: out.ExitPolicy}).NoFlag(), "fix that line", "window"},
		{&out.Error{Code: "WRITE_REQUIRES_FLAG", Hint: "re-run with --write", Exit: out.ExitPolicy}, "komando does not ask the user about this", "window"},
		{&out.Error{Code: "READ_ONLY_VIOLATION", Hint: "it changes something", Exit: out.ExitPolicy}, "komando does not ask the user about this", "window"},
		{&out.Error{Code: "SENSITIVE_FILE", Hint: "re-run with --reveal; komando asks the user in a window on their screen", Exit: out.ExitPolicy}, "--reveal", "Tell the user"},
	} {
		resetApproval()
		approvalHint(tcl, tc.e)
		if !strings.Contains(tc.e.Hint, tc.want) || tc.nope != "" && strings.Contains(tc.e.Hint, tc.nope) {
			t.Errorf("%s: %q", tc.e.Code, tc.e.Hint)
		}
	}
}

// An AI agent reading -o text gets the agent hint, not the person's "add
// --yes in a script if you are sure"; a script still gets the person's words.
func TestSafetyStopTextHintForAgents(t *testing.T) {
	invHome(t)
	noAgent(t)
	e := toErr(guardSafety(tcl, "turning off the audit log"))
	approvalHint(tcl, e)
	if !strings.Contains(e.TextHint(), "in a script") {
		t.Errorf("script: %q", e.TextHint())
	}
	asAgent(t, false, true)
	resetApproval()
	e = toErr(guardSafety(tcl, "turning off the audit log"))
	approvalHint(tcl, e)
	if h := e.TextHint(); strings.Contains(h, "in a script") || !strings.Contains(h, "komando then asks them in a window") {
		t.Errorf("agent text hint: %q", h)
	}
	if !strings.HasPrefix(e.TextMessage(), "turning off the audit log turns off") {
		t.Errorf("message: %q", e.TextMessage())
	}
}

// With host keys strict, an AI agent's first pin needs a person's yes, and
// the window shows the fingerprint to compare.
func TestFirstPinByAnAgentUnderStrict(t *testing.T) {
	st := &store.State{Settings: store.DefaultSettings()}
	noAgent(t)
	st.Settings.HostKeyPolicy = "strict"
	if err := guardFirstPin(tcl, st, []string{"web1 SHA256:abc"}); err != nil {
		t.Fatalf("a person pins it: %v", err)
	}
	asAgent(t, false, true)
	err := guardFirstPin(tcl, st, []string{"web1 SHA256:abc"})
	if oe, ok := err.(*out.Error); !ok || oe.Code != "SAFETY_SETTING" || !strings.Contains(oe.Message, "SHA256:abc") {
		t.Fatalf("agent, strict: %v", err)
	}
	st.Settings.HostKeyPolicy = "accept-new"
	if err := guardFirstPin(tcl, st, []string{"web1 SHA256:abc"}); err != nil {
		t.Fatalf("accept-new pins on first login anyway: %v", err)
	}
}

// doctor says whether AI agents have komando's skill, and whether it is this
// version's.
func TestDoctorChecksTheAgentSkill(t *testing.T) {
	invHome(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
	t.Chdir(t.TempDir())
	check := func() map[string]any {
		t.Helper()
		d, _ := invRun(t, "doctor")
		for _, c := range d["checks"].([]any) {
			if m := c.(map[string]any); m["name"] == "agent_skill" {
				return m
			}
		}
		t.Fatalf("no agent_skill check: %v", d)
		return nil
	}
	if c := check(); c["ok"] != false || !strings.Contains(c["detail"].(string), "komando guide install") {
		t.Errorf("no skill: %v", c)
	}
	mustRun(t, "guide", "install", "--no-guard")
	if c := check(); c["ok"] != true {
		t.Errorf("installed: %v", c)
	}
	p := filepath.Join(home, ".claude", "skills", "komando", "SKILL.md")
	os.WriteFile(p, []byte("an older skill\n"), 0o644)
	if c := check(); c["ok"] != false || !strings.Contains(c["detail"].(string), "another komando version") || strings.Contains(c["detail"].(string), "old spellings") {
		t.Errorf("stale: %v", c)
	}
}

func TestLogTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.log")
	os.WriteFile(p, []byte("one\ntwo\n\x1b[31mthree\x1b[0m\nfour\n"), 0o600)
	if got := logTail(p, 2); got != ": [31mthree[0m; four" && got != ": three; four" && !strings.HasSuffix(got, "; four") {
		t.Errorf("logTail: %q", got)
	}
	if logTail(filepath.Join(t.TempDir(), "none"), 3) != "" {
		t.Error("no log: empty")
	}
}

// guide uninstall takes out the skill and komando's guard entries, keeps
// the person's own hooks, and an agent cannot take its own guard away
// without a person's yes.
func TestGuideUninstall(t *testing.T) {
	invHome(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	own := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-own-check"}]}]},"model":"x"}`
	os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(own), 0o600)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o755)
	mustRun(t, "guide", "install")
	settings := func() string {
		b, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
		return string(b)
	}
	if !strings.Contains(settings(), " guide guard") {
		t.Fatalf("install: %s", settings())
	}
	asAgent(t, false, true) // the person says no
	tcl.flags.yes = true
	if _, e := invRun(t, "guide", "uninstall"); e == nil || e.Code != "SAFETY_SETTING" {
		t.Fatalf("an agent removes its guard: %+v", e)
	}
	if !strings.Contains(settings(), " guide guard") {
		t.Fatal("the guard went without the person's yes")
	}
	noAgent(t)
	mustRun(t, "guide", "uninstall", "--yes")
	s := settings()
	if strings.Contains(s, "guide guard") || !strings.Contains(s, "my-own-check") || !strings.Contains(s, `"model": "x"`) {
		t.Errorf("after uninstall: %s", s)
	}
	for _, p := range []string{filepath.Join(home, ".claude", "skills", "komando"), filepath.Join(home, ".agents", "skills", "komando")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(home, ".codex", "hooks.json")); strings.Contains(string(b), "guide guard") {
		t.Errorf("codex: %s", b)
	}
	if d := mustRun(t, "guide", "uninstall"); len(d["files"].([]any)) != 0 {
		t.Errorf("again: nothing left to remove: %v", d)
	}
}

func TestAuditActorFilter(t *testing.T) {
	f := auditFilter{actor: "claude"}
	for e, want := range map[*map[string]any]bool{
		{"actor": "budi", "agent": "Claude Code"}: true,
		{"actor": "claude-agent"}:                 true,
		{"actor": "budi", "os_user": "budi"}:      false,
	} {
		if f.keep(*e) != want {
			t.Errorf("%v: want %v", *e, want)
		}
	}
}
