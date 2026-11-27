package cli

import (
	"strings"
	"testing"
)

// Row C621: a Windows run has no session on the server, so `host winrm
// exec` takes none of exec's session flags: --attach and --wait are
// refused as USAGE, never ignored.
func TestWinRMExecRefusesSessionFlags(t *testing.T) {
	leaf, _, err := newRoot(tcl).Find([]string{"host", "winrm", "exec"})
	if err != nil || leaf.Name() != "exec" {
		t.Fatalf("host winrm exec: %v", err)
	}
	for _, n := range []string{"attach", "offset", "wait", "log-max", "stop", "signal", "remove"} {
		if leaf.Flags().Lookup(n) != nil {
			t.Errorf("host winrm exec has --%s", n)
		}
	}
	for _, args := range [][]string{
		{"host", "winrm", "exec", "win1", "--attach", "abc"},
		{"host", "winrm", "exec", "win1", "--wait", "5m", "--", "dir"},
	} {
		e := usageFor(t, args...)
		if e.Code != "USAGE" || !strings.Contains(e.Message, "unknown flag: "+args[4]) {
			t.Errorf("%v: %s %q", args, e.Code, e.Message)
		}
	}
}
