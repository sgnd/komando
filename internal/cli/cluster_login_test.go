package cli

import (
	"strings"
	"testing"
)

// A kubeconfig whose login program is not on this computer fails with the
// program's name, not with "cannot reach the cluster".
func TestClusterLoginProgramMissing(t *testing.T) {
	invHome(t)
	l := newApplyLab(t)
	user := "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: komando-test-no-such-login\n" +
		"      installHint: get it from https://login.example\n"
	mustRun(t, "import", "kubeconfig", l.kubeconfig(t, user))
	_, e := cliRun(t, "cluster", "kubernetes", "raw", "prod", "--", "get", "pods")
	// raw says it as kubectl does (TOOL_FAILED naming the program), without TOOL_MISSING and the install hint (row C496)
	if e == nil || !strings.Contains(e.Message, "komando-test-no-such-login") {
		t.Fatalf("want a failure naming the missing login program, got %+v", e)
	}
	// a login program that fails is a failed login, not an unreachable cluster
	user = "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: false\n"
	mustRun(t, "import", "kubeconfig", l.kubeconfig(t, user), "--overwrite")
	if _, e := cliRun(t, "cluster", "kubernetes", "raw", "prod", "--", "get", "pods"); e == nil {
		t.Fatalf("want a failed login, got %+v", e)
	}
}
