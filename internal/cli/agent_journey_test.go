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
		{&out.Error{Code: "POLICY_BLOCKED", Hint: "check it", Exit: out.ExitPolicy}, "komando asks the user in a window", ""},
		{(&out.Error{Code: "UNSAFE_BACKUP", Hint: "fix that line", Exit: out.ExitPolicy}).NoFlag(), "fix that line", "window"},
		{&out.Error{Code: "WRITE_REQUIRES_FLAG", Hint: "re-run with --write", Exit: out.ExitPolicy}, "komando does not ask the user about this", "window"},
		{&out.Error{Code: "READ_ONLY_VIOLATION", Hint: "it changes something", Exit: out.ExitPolicy}, "komando does not ask the user about this", "window"},
		{&out.Error{Code: "SENSITIVE_FILE", Hint: "re-run with --reveal; komando asks the user in a window on their screen", Exit: out.ExitPolicy}, "--reveal", "Tell the user"},
	} {
		resetApproval()
		approvalHint(tc.e)
		if !strings.Contains(tc.e.Hint, tc.want) || tc.nope != "" && strings.Contains(tc.e.Hint, tc.nope) {
			t.Errorf("%s: %q", tc.e.Code, tc.e.Hint)
		}
	}
}

// With host keys strict, an AI agent's first pin needs a person's yes, and
// the window shows the fingerprint to compare.
func TestFirstPinByAnAgentUnderStrict(t *testing.T) {
	st := &store.State{Settings: store.DefaultSettings()}
	noAgent(t)
	st.Settings.HostKeyPolicy = "strict"
	if err := guardFirstPin(st, []string{"web1 SHA256:abc"}); err != nil {
		t.Fatalf("a person pins it: %v", err)
	}
	asAgent(t, false, true)
	err := guardFirstPin(st, []string{"web1 SHA256:abc"})
	if oe, ok := err.(*out.Error); !ok || oe.Code != "SAFETY_SETTING" || !strings.Contains(oe.Message, "SHA256:abc") {
		t.Fatalf("agent, strict: %v", err)
	}
	st.Settings.HostKeyPolicy = "accept-new"
	if err := guardFirstPin(st, []string{"web1 SHA256:abc"}); err != nil {
		t.Fatalf("accept-new pins on first login anyway: %v", err)
	}
}

// doctor says whether AI agents have komando's skill, and whether it is this
// version's.
func TestDoctorChecksTheAgentSkill(t *testing.T) {
	invHome(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
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
	if c := check(); c["ok"] != false || !strings.Contains(c["detail"].(string), "another komando version") {
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
