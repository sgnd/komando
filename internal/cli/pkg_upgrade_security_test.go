package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// `pkg upgrade --security` is the security rollout `pkg security --apply`
// was: the same stops, the ID pkg.security, a read-only gate key refuses
// it, and --apply still works, noted in meta.deprecated (C-V18).
func TestPkgUpgradeSecurity(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@127.0.0.1", "--port", "2")
	mustRun(t, "host", "edit", "web1", "--protected")
	if e := wantCode(t, "PROTECTED_HOST", "pkg", "upgrade", "web1", "--security"); e.Exit != out.ExitPolicy {
		t.Errorf("exit %d", e.Exit)
	}
	code, text := runMain(t, "pkg", "upgrade", "web1", "--security", "--dry-run")
	if !strings.Contains(text, `"command":"pkg.security"`) || !strings.Contains(text, "would_be_blocked") { // the closed port fails then
		t.Errorf("dry run: exit %d %s", code, text)
	}
	code, text = runMain(t, "pkg", "upgrade", "web1", "--security")
	if code != out.ExitPolicy || !strings.Contains(text, `"command":"pkg.security"`) {
		t.Errorf("stop: exit %d %s", code, text)
	}
	code, text = runMain(t, "pkg", "security", "web1", "--apply", "--dry-run")
	if !strings.Contains(text, `"deprecated":{"used":"komando pkg security --apply","now":"komando pkg upgrade TARGET --security"}`) {
		t.Errorf("--apply: exit %d %s", code, text)
	}
	wantCode(t, "USAGE", "pkg", "upgrade", "web1", "nginx", "--security")
	wantCode(t, "USAGE", "pkg", "upgrade", "web1", "--keep-going")
	if got := spellingAnswer(t, "pkg.upgrade", "--security", ""); got != "SSH_GATE_READ_ONLY" {
		t.Errorf("read-only gate key: %q", got)
	}
	if r := riskOfLine([]string{"pkg", "upgrade", "web1", "--security"}); r.tier != tierDangerous {
		t.Errorf("risk: %+v", r)
	}
	if f := findCmd(t, newRoot(), "pkg", "security").Flags().Lookup("apply"); f == nil || !f.Hidden {
		t.Error("pkg security --apply must be hidden")
	}
}

// `pkg upgrade @web --security` goes one server at a time and stops at the
// first that fails: the next is never reached (C-V18, the serial rollout).
func TestPkgUpgradeSecurityOneAtATime(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@127.0.0.1", "--port", "1", "-g", "web")
	mustRun(t, "host", "add", "web2", "root@127.0.0.1", "--port", "2", "-g", "web")
	code, text := runMain(t, "pkg", "upgrade", "@web", "--security")
	if code == 0 || !strings.Contains(text, `"order":"one server at a time, stopping at a failure or an unexpected change"`) ||
		!strings.Contains(text, `"not_run":["web2"]`) || strings.Contains(text, `"host":"web2"`) {
		t.Errorf("exit %d %s", code, text)
	}
}
