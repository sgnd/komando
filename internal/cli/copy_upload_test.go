package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copy to a storage conn or from one, to a server or from one, is one code
// path; the checks here stop before any server is contacted.
func TestTransferOnePath(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	mustRun(t, "conn", "add", "bk", "s3://AKIAEXAMPLE@shop-dev/backups?region=eu-west-1")
	f := filepath.Join(t.TempDir(), "a.txt")
	_ = os.WriteFile(f, []byte("hello\n"), 0o600)
	for _, args := range [][]string{
		{"copy", f, "bk:a.txt", "--sudo"},
		{"copy", f, "bk:a.txt", "-p"},
		{"copy", "bk:a.txt", t.TempDir(), "--sudo"},
		{"copy", "bk:logs/", "-", "-r"},
		{"copy", "web1:/etc/hosts", "-", "--sudo"},
		{"copy", "web1:/var/www", ".", "-r", "--sudo"},
	} {
		if e := wantCode(t, "USAGE", args...); e.Exit != 2 {
			t.Errorf("%v: exit %d", args, e.Exit)
		}
	}
	// a copy to a server and one from it say their direction
	up := mustRun(t, "--dry-run", "copy", f, "web1:/tmp/a.txt")
	if up["dst"] != "web1:/tmp/a.txt" || up["direction"] != "upload" {
		t.Errorf("copy to a server: %v", up)
	}
	down := mustRun(t, "--dry-run", "copy", "web1:/etc/hosts", "./x/")
	if down["direction"] != "download" || down["src"] != "web1:/etc/hosts" {
		t.Errorf("copy from a server: %v", down)
	}
}

// --sync takes --delete, --emptied and --exclude and refuses the flags of a
// file copy, and those flags need --sync: all before any server is contacted.
func TestCopyOptionRules(t *testing.T) {
	invHome(t)
	for _, args := range [][]string{
		{"copy", "./a", "web1:/b", "--delete"},
		{"copy", "./a", "web1:/b", "--exclude", ".git"},
		{"copy", "./a", "web1:/b", "--emptied", "x"},
		{"copy", "./a", "web1:/b", "--sync", "-r"},
		{"copy", "./a", "web1:/b", "--sync", "--continue"},
		{"copy", "./a", "web1:/b", "--sync", "--mode", "0644"},
	} {
		if e := wantCode(t, "USAGE", args...); e.Exit != 2 {
			t.Errorf("%v: exit %d", args, e.Exit)
		}
	}
}

// stderrOf runs fn and returns what it wrote on stderr.
func stderrOf(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := tcl.out.Err
	tcl.out.Err = w
	fn()
	tcl.out.Err = saved
	_ = w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

// exec --script runs a local script: the file goes to the interpreter as
// its input, with --arg as $1 ...
func TestExecScript(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	f := filepath.Join(t.TempDir(), "deploy.sh")
	_ = os.WriteFile(f, []byte("#!/bin/bash\necho hi\n"), 0o600)
	for _, args := range [][]string{
		{"exec", "web1", "--script", f, "--", "uptime"},
		{"exec", "web1", "--script", f, "-c", "uptime"},
		{"exec", "web1", "--arg", "x", "--", "uptime"},
		{"exec", "web1", "--interpreter", "python3", "--", "uptime"},
		{"exec", "web1", "--script", f, "--stdin-file", f},
		{"exec", "web1", "--script", f, "--pty"},
	} {
		wantCode(t, "USAGE", args...)
	}
	var plan map[string]any
	note := stderrOf(t, func() {
		plan = mustRun(t, "--dry-run", "exec", "web1", "--script", f, "--arg", "v1")
	})
	if note != "" {
		t.Errorf("exec --script printed %q", note)
	}
	delete(plan, "_meta")
	want := "bash -s -- 'v1'"
	if s := strings.Join(strings.Fields(strings.ReplaceAll(stringOf(plan), "\\", "")), " "); !strings.Contains(s, want) {
		t.Errorf("plan has no %q: %v", want, plan)
	}
	if code, _ := runMain(t, "script", "web1", f); code == 0 {
		t.Error("script, an old name of exec --script, still runs")
	}
}

func stringOf(v any) string {
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			b.WriteString(x + " ")
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(v)
	return b.String()
}
