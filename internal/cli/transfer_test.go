package cli

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// flagNames lists a command's own flags.
func flagNames(c *cobra.Command) []string {
	var l []string
	c.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) { l = append(l, f.Name) })
	slices.Sort(l)
	return l
}

// storage upload/download are upload/download for storage conns: the same
// code, with only the flags that mean something for storage.
func TestStorageTransferIsUploadDownload(t *testing.T) {
	root := newRoot()
	find := func(path string) *cobra.Command {
		c, _, err := root.Find(strings.Fields(path))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if got := flagNames(find("storage upload")); !slices.Equal(got, []string{"recursive"}) {
		t.Errorf("storage upload flags: %v", got)
	}
	if got := flagNames(find("storage download")); !slices.Equal(got, []string{"overwrite", "recursive", "to"}) {
		t.Errorf("storage download flags: %v", got)
	}
	for _, p := range []string{"storage upload", "storage download"} {
		if c := find(p); c.Hidden || !strings.HasPrefix(c.Short, "Same as `komando ") {
			t.Errorf("%s: hidden %v, short %q", p, c.Hidden, c.Short)
		}
	}
	for _, p := range []string{"upload", "download"} {
		for _, f := range flagNames(find("storage " + p)) {
			if find(p).Flags().Lookup(f) == nil {
				t.Errorf("storage %s has --%s, %s has not", p, f, p)
			}
		}
	}
	if got := cmdName(find("storage upload")); got != "storage.upload" {
		t.Errorf("JSON name %q", got)
	}
	if got := cmdName(find("cp")); got != "cp" {
		t.Errorf("JSON name %q", got)
	}
}

// upload, storage upload and cp give the same answers, because they are
// one code path; the checks here stop before any server is contacted.
func TestTransferOnePath(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	mustRun(t, "conn", "add", "bk", "s3://AKIAEXAMPLE@shop-dev/backups?region=eu-west-1")
	f := filepath.Join(t.TempDir(), "a.txt")
	_ = os.WriteFile(f, []byte("hello\n"), 0o600)
	for _, args := range [][]string{
		{"upload", "bk", f, "--sudo"},
		{"cp", f, "bk:a.txt", "--sudo"},
		{"cp", f, "bk:a.txt", "-p"},
		{"download", "bk", "a.txt", "--sudo"},
		{"cp", "bk:a.txt", t.TempDir(), "--sudo"},
		{"storage", "download", "bk", "logs/", "-r", "--to", "-"},
		{"download", "bk", "logs/", "-r", "--to", "-"},
		{"download", "web1", "/etc/hosts", "--to", "-"},
		{"download", "web1", "/var/www", "-r", "--sudo"},
	} {
		if e := wantCode(t, "USAGE", args...); e.Exit != 2 {
			t.Errorf("%v: exit %d", args, e.Exit)
		}
	}
	// --sudo is no storage flag
	if _, e := invRun(t, "storage", "upload", "bk", f, "--sudo"); e == nil || !strings.Contains(e.Message, "unknown flag") {
		t.Errorf("storage upload --sudo: %+v", e)
	}
	// storage upload is for storage conns only
	if _, e := invRun(t, "storage", "upload", "web1", f); e == nil {
		t.Error("storage upload to a server ran")
	}
	// cp to a server is upload to a server: same dry-run plan
	up := mustRun(t, "--dry-run", "upload", "web1", f, "/tmp/a.txt")
	cp := mustRun(t, "--dry-run", "cp", f, "web1:/tmp/a.txt")
	if up["dst"] != "web1:/tmp/a.txt" || cp["dst"] != up["dst"] || cp["direction"] != "upload" {
		t.Errorf("upload %v, cp %v", up, cp)
	}
	down := mustRun(t, "--dry-run", "cp", "web1:/etc/hosts", "./x/")
	if down["direction"] != "download" || down["src"] != "web1:/etc/hosts" {
		t.Errorf("cp download %v", down)
	}
}

// stderrOf runs fn and returns what it wrote on stderr.
func stderrOf(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = saved
	_ = w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

// exec --script runs a local script; script is its old name for one
// release and says so on stderr.
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
	if scriptCmd().Flags().Lookup("stdin-file") != nil {
		t.Error("the old script name takes --stdin-file, which a script cannot use")
	}
	var plan, old map[string]any
	note := stderrOf(t, func() {
		plan = mustRun(t, "--dry-run", "exec", "web1", "--script", f, "--arg", "v1")
	})
	if note != "" {
		t.Errorf("exec --script printed %q", note)
	}
	note = stderrOf(t, func() {
		old = mustRun(t, "--dry-run", "script", "web1", f, "--arg", "v1")
	})
	if !strings.Contains(note, "use `komando exec TARGET --script FILE` now") {
		t.Errorf("script note: %q", note)
	}
	want := "bash -s -- 'v1'"
	for _, d := range []map[string]any{plan, old} {
		if s := strings.Join(strings.Fields(strings.ReplaceAll(stringOf(d), "\\", "")), " "); !strings.Contains(s, want) {
			t.Errorf("plan has no %q: %v", want, d)
		}
	}
	root := newRoot()
	c, _, _ := root.Find([]string{"script"})
	if !c.Hidden {
		t.Error("script is listed")
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
