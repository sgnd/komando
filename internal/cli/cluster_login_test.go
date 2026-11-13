package cli

import (
	"strings"
	"testing"
)

// A kubeconfig whose login program is not on this computer says so, with
// the kubeconfig's own installHint, instead of "cannot reach the cluster".
func TestClusterLoginProgramMissing(t *testing.T) {
	invHome(t)
	l := newApplyLab(t)
	user := "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: komando-test-no-such-login\n" +
		"      installHint: get it from https://login.example\n"
	mustRun(t, "import", "kubeconfig", l.kubeconfig(t, user))
	_, e := cliRun(t, "cluster", "ls", "prod", "pods")
	if e == nil || e.Code != "TOOL_MISSING" || !strings.Contains(e.Message, "komando-test-no-such-login") ||
		!strings.Contains(e.Hint, "https://login.example") || e.Exit != 3 {
		t.Fatalf("want TOOL_MISSING (exit 3) with the install hint, got %+v", e)
	}
	// a login program that fails is a failed login, not an unreachable cluster
	user = "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: false\n"
	mustRun(t, "import", "kubeconfig", l.kubeconfig(t, user), "--overwrite")
	if _, e := cliRun(t, "cluster", "ls", "prod", "pods"); e == nil || e.Code != "LOGIN_FAILED" || e.Exit != 4 {
		t.Fatalf("want LOGIN_FAILED (exit 4), got %+v", e)
	}
}
