package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// listToolWords are the list commands whose verb is a tool's own word
// (S-3.3): each has --limit like every list/ls (S-5.8).
var listToolWords = map[string]bool{
	"komando docker ps": true, "komando docker images": true, "komando docker stats": true,
	"komando pkg installed": true, "komando pkg upgradable": true,
	"komando queue groups": true, "komando db activity": true, "komando db locks": true,
	"komando db sizes": true, "komando cache keys": true, "komando net ports": true,
	"komando cluster history": true, "komando cluster helm history": true, "komando cluster events": true,
	"komando audit": true,
	// the log readers: the last N lines
	"komando logs": true, "komando svc logs": true, "komando docker logs": true,
	"komando cluster logs": true, "komando job logs": true,
}

// TestStandardListLimit: every list command has --limit (S-5.8), the log
// readers keep --tail as a hidden spelling of it, and -n is --limit
// outside cluster.
func TestStandardListLimit(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
		}
		if !c.Runnable() || c.Hidden || c.Parent() == nil {
			return
		}
		path := c.CommandPath()
		if !listToolWords[path] && c.Name() != "list" && c.Name() != "ls" {
			return
		}
		f := c.Flags().Lookup("limit")
		if f == nil {
			t.Errorf("%s: a list command has no --limit (S-5.8)", path)
			return
		}
		if f.Value.Type() != "int" {
			t.Errorf("%s: --limit is %s, want int", path, f.Value.Type())
		}
		inCluster := strings.HasPrefix(path, "komando cluster ")
		if want := map[bool]string{true: "", false: "n"}[inCluster]; f.Shorthand != want {
			t.Errorf("%s: --limit shorthand %q, want %q", path, f.Shorthand, want)
		}
		if strings.HasSuffix(path, " logs") {
			tail := c.Flags().Lookup("tail")
			if tail == nil || !tail.Hidden || tail.Value != f.Value {
				t.Errorf("%s: --tail must be a hidden spelling of --limit", path)
			}
		}
	}
	walk(newRoot())
}

// A list that stops at --limit sets meta.truncated; one that shows
// everything does not. Count is what is shown.
func TestListLimitTruncated(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "a1", "u@10.0.0.1")
	mustRun(t, "host", "add", "a2", "u@10.0.0.2")
	mustRun(t, "host", "add", "a3", "u@10.0.0.3")
	for _, args := range [][]string{{"list"}, {"host", "list"}, {"ls"}} {
		d := mustRun(t, append(args, "-n", "2")...)
		if d["count"].(float64) != 2 || len(d["targets"].([]any)) != 2 {
			t.Errorf("%v -n 2: %v", args, d)
		}
		if m := d["_meta"].(map[string]any); m["truncated"] != true {
			t.Errorf("%v -n 2: meta.truncated not set: %v", args, m)
		}
		d = mustRun(t, append(args, "--limit", "0")...)
		if d["count"].(float64) != 3 {
			t.Errorf("%v --limit 0: %v", args, d)
		}
		if m := d["_meta"].(map[string]any); m["truncated"] != nil {
			t.Errorf("%v --limit 0: meta.truncated set: %v", args, m)
		}
		if d = mustRun(t, append(args, "-n", "3")...); d["_meta"].(map[string]any)["truncated"] != nil {
			t.Errorf("%v -n 3 shows all three: meta.truncated set", args)
		}
	}
	// the default stays: no limit where there was none
	if d := mustRun(t, "list"); d["count"].(float64) != 3 {
		t.Errorf("list: %v", d)
	}
	// group list: groups and members both stop at --limit
	mustRun(t, "group", "add", "web", "a1,a2,a3")
	d := mustRun(t, "group", "list", "web", "-n", "1")
	if m := d["members"].([]any); len(m) != 1 || m[0] != "a1" {
		t.Errorf("group list web -n 1: %v", d)
	}
}

// fs list: -n/--limit keeps its default of 1000; --limit 0 lists
// everything.
func TestFsLsLimitSpelling(t *testing.T) {
	f := fsLsCmd().Flags().Lookup("limit")
	if f == nil || f.Shorthand != "n" || f.DefValue != "1000" {
		t.Fatalf("fs list --limit: %+v", f)
	}
}

// job logs: -n/--limit is primary (default 0, read from --offset); --tail
// is a permanent hidden synonym.
func TestJobLogsLimit(t *testing.T) {
	c := jobLogsCmd()
	f := c.Flags().Lookup("limit")
	if f == nil || f.Shorthand != "n" || f.DefValue != "0" {
		t.Fatalf("job logs --limit: %+v", f)
	}
	tail := c.Flags().Lookup("tail")
	if tail == nil || !tail.Hidden || tail.Value != f.Value {
		t.Fatalf("job logs --tail must be a silent synonym of --limit: %+v", tail)
	}
}
