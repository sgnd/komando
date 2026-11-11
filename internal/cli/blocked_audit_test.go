package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// runMain runs komando through Execute, as the program does, and returns
// the exit code and what it printed.
func runMain(t *testing.T, args ...string) (int, string) {
	t.Helper()
	g.dryRun, g.yes, g.allowDangerous = false, false, false
	saved, savedW := os.Args, out.P.W
	var buf bytes.Buffer
	out.P.W = &buf
	os.Args = append([]string{"komando", "-o", "json"}, args...)
	defer func() { os.Args, out.P.W = saved, savedW }()
	return Execute(), buf.String()
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
	want := "host.rm=PROTECTED_HOST policy.rm=SAFETY_SETTING exec=PROTECTED_HOST"
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
