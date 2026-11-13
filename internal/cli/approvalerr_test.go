package cli

import (
	"os"
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

// The script hint repeats the command line only when it holds no value
// that may be a secret: words for another program after --, free text (a
// word with a space or quote), a value the mask would hide, or the value
// of a flag such as --content. Those get the same sentence without the
// line, so a password never lands in error.hint or a CI log (review F9).
func TestApprovalHintHidesSecrets(t *testing.T) {
	invHome(t)
	noAgent(t)
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	for _, c := range []struct {
		args []string
		line string // the line the hint repeats, or "" for none
	}{
		{[]string{"reboot", "web1"}, "`komando reboot web1 --allow-dangerous`"},
		{[]string{"-o", "json", "fs", "rm", "web1", "/tmp/x"}, "`komando -o json fs rm web1 /tmp/x --allow-dangerous`"},
		{[]string{"exec", "web1", "--", "mysql", "-pS3cret", "-e", "drop table x"}, ""},
		{[]string{"exec", "web1", "--", "sshpass", "-p", "S3cret", "ssh", "x"}, ""},
		{[]string{"db", "query", "db1", "--write", "UPDATE u SET pw='S3cret'"}, ""},
		{[]string{"fs", "write", "prod1", "/tmp/x", "--content", "S3cret"}, ""},
		{[]string{"fs", "write", "prod1", "/tmp/x", "--content=S3cret"}, ""},
		{[]string{"host", "add", "x", "u@h", "--env", "DB_PASSWORD=S3cret"}, ""},
	} {
		os.Args = append([]string{"komando"}, c.args...)
		h := approvalText([]string{"--allow-dangerous"}, false, false)
		if strings.Contains(h, "S3cret") {
			t.Errorf("%v: the hint holds the secret: %q", c.args, h)
		}
		if !strings.Contains(h, "--allow-dangerous") {
			t.Errorf("%v: the hint names no flag: %q", c.args, h)
		}
		if c.line != "" && !strings.HasSuffix(h, ": "+c.line) {
			t.Errorf("%v: %q, want the line %s", c.args, h, c.line)
		}
		if c.line == "" && strings.Contains(h, "`") {
			t.Errorf("%v: a line was repeated: %q", c.args, h)
		}
	}
}
