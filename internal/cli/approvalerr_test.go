package cli

import (
	"strings"
	"testing"
)

// TestApprovalErr: every stop a flag lifts gets the one approval hint
// (S-8.6, C-C10), in the agent and the script variant, naming every flag
// the real run needs.
func TestApprovalErr(t *testing.T) {
	invHome(t)
	for code, flag := range map[string]string{"POLICY_BLOCKED": "--allow-dangerous", "PROTECTED_HOST": "--yes", "PROTECTED_TARGET": "--yes",
		"SAFETY_SETTING": "--yes", "SECRET_DESTINATION": "--yes", "OPEN_BIND": "--yes", "CONFIRM_REQUIRED": "--yes"} {
		noAgent(t)
		t.Setenv("CLAUDECODE", "1")
		resetApproval()
		e := approvalErr(code, "why")
		if e.Message != "why" || e.Exit != 6 || e.Hint != approvalText([]string{flag}, true, false) {
			t.Errorf("%s for an agent: %+v", code, e)
		}
		noAgent(t)
		if e := approvalErr(code, "why"); !strings.HasPrefix(e.Hint, "check with --dry-run, then run it again with "+flag+": `komando ") {
			t.Errorf("%s for a script: %q", code, e.Hint)
		}
	}
	e := approvalErr("POLICY_BLOCKED", "why", "--yes")
	if !strings.Contains(e.Hint, "--allow-dangerous and --yes") {
		t.Errorf("a protected target's stop names one flag: %q", e.Hint)
	}
}
