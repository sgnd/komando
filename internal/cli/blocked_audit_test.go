package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// runMain runs komando through Execute, as the program does, and returns
// the exit code and what it printed.
func runMain(t *testing.T, args ...string) (int, string) {
	t.Helper()
	tcl.flags.dryRun, tcl.flags.yes, tcl.flags.allowDangerous = false, false, false
	saved, savedW := tcl.args, tcl.out.W
	var buf bytes.Buffer
	tcl.out.W = &buf
	tcl.args = append([]string{"komando", "-o", "json"}, args...)
	defer func() { tcl.args, tcl.out.W = saved, savedW }()
	return executeArgs(tcl.args[1:]), buf.String()
}

// Every blocked attempt is a line in the audit log, once, also where the
// command itself records nothing (host rm of a protected server, removing
// a deny rule), and the text view says "blocked".
func TestBlockedAttemptsAreAudited(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web2", "u@10.0.0.2", "--protected")
	mustRun(t, "policy", "deny", "foo.*bar")
	if code, _ := runMain(t, "host", "rm", "web2"); code != out.ExitPolicy {
		t.Fatalf("host rm: exit %d", code)
	}
	if code, _ := runMain(t, "policy", "rm", "foo.*bar"); code != out.ExitPolicy {
		t.Fatalf("policy rm: exit %d", code)
	}
	if code, _ := runMain(t, "exec", "web2", "--", "touch", "/tmp/x"); code != out.ExitPolicy {
		t.Fatalf("exec: exit %d", code)
	}
	if code, _ := runMain(t, "host", "rm", "web2", "--dry-run"); code != 0 {
		t.Fatalf("dry run: exit %d", code)
	}
	d := mustRun(t, "audit", "--failed", "-n", "0")
	var got []string
	for _, e := range d["entries"].([]any) {
		m := e.(map[string]any)
		got = append(got, m["command"].(string)+"="+m["blocked"].(string))
	}
	want := "host.rm=PROTECTED_TARGET policy.rm=SAFETY_SETTING exec=PROTECTED_TARGET"
	if strings.Join(got, " ") != want {
		t.Errorf("blocked in the audit: %v, want %s", got, want)
	}
	if d := mustRun(t, "audit", "--failed", "--target", "web2", "-n", "0"); d["count"] != float64(2) {
		t.Errorf("the blocked host rm and exec name web2: %v", d["entries"])
	}
	_, text := runMain(t, "audit", "--failed", "-n", "1", "-o", "text")
	if !strings.Contains(text, "blocked") || strings.Contains(text, "FAILED") {
		t.Errorf("text: %q", text)
	}
}

// guide install writes files on this computer, so it is audited.
func TestGuideInstallIsAudited(t *testing.T) {
	invHome(t)
	t.Chdir(t.TempDir())
	mustRun(t, "guide", "install", "--project", "--no-guard")
	d := mustRun(t, "audit", "--command", "guide", "-n", "0")
	if d["count"] != float64(1) {
		t.Errorf("audit: %v", d)
	}
	mustRun(t, "guide", "install", "--project", "--no-guard") // nothing changed: nothing to record
	if d := mustRun(t, "audit", "--command", "guide", "-n", "0"); d["count"] != float64(1) {
		t.Errorf("second run: %v", d)
	}
}

// A blocked command given a selector (@group, tag:, a pattern) records the
// servers and conns it picked, not "-": `audit --target web2` finds it.
func TestBlockedAttemptNamesSelectedTargets(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web2", "u@10.0.0.2", "--protected", "--group", "prod")
	mustRun(t, "host", "add", "web3", "u@10.0.0.3", "--protected", "--tag", "edge")
	for _, sel := range []string{"@prod", "tag:edge"} {
		if code, _ := runMain(t, "host", "rm", sel); code != out.ExitPolicy {
			t.Fatalf("host rm %s: exit %d", sel, code)
		}
	}
	for _, name := range []string{"web2", "web3"} {
		if d := mustRun(t, "audit", "--failed", "--target", name, "-n", "0"); d["count"] != float64(1) {
			t.Errorf("the blocked host rm names %s: %v", name, d["entries"])
		}
	}
}

// The audit log keeps no password a command line carried: the command an
// exec, job start or cluster exec ran is recorded with what looks like a
// password, key or token hidden, as the ssh-gate's records are. The copy
// sent to a syslog server is the same record.
func TestAuditRecordHidesSecretsInTheCommand(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.9")
	st := mustState(t)
	audit(tcl, st, "exec", []string{"web1"}, "PGPASSWORD=Sup3rS3cretValue99 psql --password=hunter2222x -h db -c 'select 1'", true, nil)
	d := mustRun(t, "audit", "-n", "0")
	b, _ := json.Marshal(d)
	for _, leak := range []string{"Sup3rS3cretValue99", "hunter2222x"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("the audit log holds %s: %s", leak, b)
		}
	}
	if !strings.Contains(string(b), "psql") || !strings.Contains(string(b), "select 1") || !strings.Contains(string(b), "[hidden]") {
		t.Errorf("the rest of the command stays readable: %s", b)
	}
}
