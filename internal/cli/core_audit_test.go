package cli

import (
	"fmt"
	"strings"
	"testing"
)

// An import with --overwrite skips a protected conn, as it skips a
// protected server, and its dry run says the same as the real run.
func TestImportOverwriteSkipsProtectedConn(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "r1", "redis://127.0.0.1:6379/0", "--protected")
	mustRun(t, "host", "add", "w1", "u@10.0.0.1", "--protected")
	mustRun(t, "conn", "add", "p1", "postgres://u@127.0.0.1/app")
	file := writeTemp(t, "exp.json", `{"format":"komando-export/1",
		"hosts":[{"name":"w1","address":"10.0.0.9","user":"u"}],
		"conns":[{"name":"r1","kind":"redis","url":"redis://127.0.0.1:6380/0"},
		         {"name":"p1","kind":"postgres","url":"postgres://u@127.0.0.1/other"}]}`)
	for _, dry := range []bool{true, false} {
		args := []string{"import", "komando", file, "--overwrite"}
		if dry {
			args = append(args, "--dry-run")
		}
		d := mustRun(t, args...)
		if got := fmt.Sprint(d["conns"]); got != "[p1]" {
			t.Errorf("dry run %v: conns %s, want [p1]", dry, got)
		}
		skipped := fmt.Sprint(d["skipped"])
		if !strings.Contains(skipped, "name:r1 reason:protected") || !strings.Contains(skipped, "name:w1 reason:protected") {
			t.Errorf("dry run %v: skipped %s", dry, skipped)
		}
	}
	if d := mustRun(t, "conn", "show", "r1"); !strings.Contains(fmt.Sprint(d["url"]), ":6379") {
		t.Errorf("the protected conn changed: %v", d)
	}
}
