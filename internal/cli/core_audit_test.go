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

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "''",
		"root":                 "root",
		"/usr/local/bin/k":     "/usr/local/bin/k",
		"a b":                  "'a b'",
		"x;rm -rf ~":           "'x;rm -rf ~'",
		"it's":                 `'it'\''s'`,
		"$(id)":                "'$(id)'",
		"a\nb":                 "'a\nb'",
		"secret:web1-pass,x=1": "secret:web1-pass,x=1",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// host rm names every server and conn that goes through the server, so one
// round of edits clears them all.
func TestHostRmInUseNamesEveryUser(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "b1", "u@10.0.0.1")
	mustRun(t, "host", "add", "h1", "u@10.0.0.2", "--via", "b1")
	mustRun(t, "conn", "add", "c1", "redis://10.0.0.3:6379/0", "--via", "b1")
	e := wantCode(t, "HOST_IN_USE", "host", "rm", "b1")
	for _, want := range []string{"server h1", "conn c1"} {
		if !strings.Contains(e.Message, want) {
			t.Errorf("message %q lacks %q", e.Message, want)
		}
	}
	for _, want := range []string{"komando host edit h1 --unset via", "komando conn edit c1 --unset via"} {
		if !strings.Contains(e.Hint, want) {
			t.Errorf("hint %q lacks %q", e.Hint, want)
		}
	}
}
