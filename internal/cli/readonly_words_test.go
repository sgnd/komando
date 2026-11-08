package cli

import (
	"fmt"
	"testing"
)

// wouldBlock is the code of the stop a --dry-run reports, or "".
func wouldBlock(t *testing.T, args ...string) string {
	t.Helper()
	d, e := cliRun(t, append([]string{"--dry-run"}, args...)...)
	if e != nil {
		t.Fatalf("%v: %+v", args, e)
	}
	wb, _ := d["_meta"].(map[string]any)["would_be_blocked"].(map[string]any)
	return fmt.Sprint(wb["code"])
}

// docker exec --read-only keeps exec's promise: a command that clearly
// changes something is refused, and on a protected server only commands
// komando knows read skip --yes.
func TestDockerExecReadOnly(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "db1", "deploy@10.0.0.2", "--protected")
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"docker", "exec", "db1", "api", "--read-only", "--", "cat", "/app/config.yml"}, "<nil>"},
		{[]string{"docker", "exec", "db1", "api", "--read-only", "--", "sh", "-c", "ls /data | wc -l"}, "<nil>"},
		{[]string{"docker", "exec", "db1", "api", "--read-only", "--", "myapp", "report"}, "PROTECTED_HOST"},
		{[]string{"docker", "exec", "db1", "api", "--read-only", "--", "sh", "-c", "ls /data; ./reset.sh"}, "PROTECTED_HOST"},
		{[]string{"docker", "exec", "db1", "api", "--", "cat", "/app/config.yml"}, "PROTECTED_HOST"},
		{[]string{"docker", "exec", "web1", "api", "--read-only", "--", "rm", "-f", "/tmp/cache"}, "READ_ONLY_VIOLATION"},
		{[]string{"docker", "exec", "web1", "api", "--read-only", "--", "sh", "-c", "echo x > /data/flag"}, "READ_ONLY_VIOLATION"},
		{[]string{"docker", "exec", "web1", "api", "--read-only", "--", "myapp", "report"}, "<nil>"}, // not protected
	} {
		if got := wouldBlock(t, c.args...); got != c.want {
			t.Errorf("%v: would be blocked by %s, want %s", c.args, got, c.want)
		}
	}
	// an interpreter running a file komando cannot see, as with exec
	if got := wouldBlock(t, "docker", "exec", "web1", "api", "--read-only", "--", "php", "artisan", "migrate:status"); got != "READ_ONLY_VIOLATION" {
		t.Errorf("php artisan under --read-only: %s", got)
	}
	if _, e := cliRun(t, "docker", "exec", "web1", "api", "--read-only", "--", "rm", "-f", "/tmp/cache"); e == nil || e.Code != "READ_ONLY_VIOLATION" {
		t.Errorf("a write under --read-only: %+v", e)
	}
}

// cluster exec --read-only rates the command a read (driver.RiskRead) only
// when komando knows it reads; on a protected cluster anything else needs
// --yes, and a clear change is refused.
func TestClusterExecReadOnly(t *testing.T) {
	invHome(t)
	l := newLabCluster(t)
	mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, "    token: test-token-abcdef"))
	mustRun(t, "conn", "edit", "prod", "--protected")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"cluster", "exec", "prod", "pod-a", "--read-only", "--", "cat", "/app/config.yml"}, "<nil>"},
		{[]string{"cluster", "exec", "prod", "pod-a", "--read-only", "--", "printenv"}, "<nil>"},
		{[]string{"cluster", "exec", "prod", "pod-a", "--read-only", "--", "sh", "-c", "echo out; echo err >&2; exit 3"}, "<nil>"},
		{[]string{"cluster", "exec", "prod", "pod-a", "--read-only", "--", "myapp", "report"}, "PROTECTED_TARGET"},
		{[]string{"cluster", "exec", "prod", "pod-a", "--", "cat", "/app/config.yml"}, "PROTECTED_TARGET"},
		{[]string{"cluster", "exec", "prod", "pod-a", "--read-only", "--", "rm", "-rf", "/tmp/cache"}, "READ_ONLY_VIOLATION"},
	} {
		if got := wouldBlock(t, c.args...); got != c.want {
			t.Errorf("%v: would be blocked by %s, want %s", c.args, got, c.want)
		}
	}
}
