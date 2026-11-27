package cli

import "testing"

// C363 (issue 490): on a protected cluster conn, `cluster run` with a
// kubectl delete or a scale to zero (rule kubectl-scale-zero) is dangerous
// and needs --allow-dangerous, and as a change it also needs --yes through
// GuardConns. The typed-name confirm of cluster rm is not what holds these
// back (cut step D4 removes it); this pins the stops that do, for the
// Kubernetes provider.
func TestProtectedClusterRunNeedsYes(t *testing.T) {
	invHome(t)
	noAgent(t)
	l := newLabCluster(t)
	mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, "    token: test-token-abcdef"))
	mustRun(t, "conn", "edit", "prod", "--protected")
	run := func(flags []string, words ...string) string {
		args := append([]string{"cluster", "run", "prod"}, flags...)
		_, e := cliRun(t, append(append(args, "--"), words...)...)
		return guardCode(e)
	}
	for _, words := range [][]string{
		{"delete", "pod", "pod-a"},
		{"scale", "deploy/api", "--replicas=0"},
	} {
		for _, s := range []struct {
			flags []string
			want  string
		}{
			{nil, "POLICY_BLOCKED"},
			{[]string{"--allow-dangerous"}, "PROTECTED_TARGET"},
			{[]string{"--yes"}, "POLICY_BLOCKED"},
			{[]string{"--allow-dangerous", "--yes"}, ""},
		} {
			if got := run(s.flags, words...); got != s.want {
				t.Errorf("%v %v: stop %q, want %q", words, s.flags, got, s.want)
			}
		}
	}
	// a plain change is held by --yes alone
	if got := run(nil, "scale", "deploy/api", "--replicas=3"); got != "PROTECTED_TARGET" {
		t.Errorf("scale to 3 without --yes: stop %q, want PROTECTED_TARGET", got)
	}
	if got := run([]string{"--yes"}, "scale", "deploy/api", "--replicas=3"); got != "" {
		t.Errorf("scale to 3 with --yes was stopped: %q", got)
	}
}
