package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// findCmd finds the command komando runs for args, through aliases.
func findCmd(t *testing.T, root *cobra.Command, args ...string) *cobra.Command {
	t.Helper()
	c, rest, err := root.Find(args)
	if err != nil || c == root || len(rest) > 0 {
		t.Fatalf("%v: no command (%v, rest %v)", args, err, rest)
	}
	return c
}

// A renamed command's ID is its new path; its plain synonym (mv, get, ls)
// runs the same command (S-1.7).
func TestStandardRenamedIDs(t *testing.T) {
	root := newRoot(tcl)
	for _, c := range []struct {
		now, old []string
		id       string
	}{
		{[]string{"conn", "rename"}, []string{"conn", "mv"}, "conn.rename"},
		{[]string{"vpn", "wireguard", "list"}, []string{"vpn", "wireguard", "ls"}, "vpn.wireguard.list"},
		{[]string{"group", "rename"}, []string{"group", "mv"}, "group.rename"},
		{[]string{"db", "user", "list"}, []string{"db", "user", "ls"}, "db.user.list"},
		{[]string{"fs", "list"}, []string{"fs", "ls"}, "fs.list"},
		{[]string{"queue", "kafka", "topic", "list"}, []string{"queue", "kafka", "topic", "ls"}, "queue.kafka.topic.list"},
		{[]string{"queue", "kafka", "topic", "show"}, []string{"queue", "kafka", "topic", "describe"}, "queue.kafka.topic.show"},
		{[]string{"registry", "oci", "image", "list"}, []string{"registry", "oci", "image", "ls"}, "registry.oci.image.list"},
		{[]string{"storage", "s3", "object", "list"}, []string{"storage", "s3", "object", "ls"}, "storage.s3.object.list"},
	} {
		now, old := findCmd(t, root, c.now...), findCmd(t, root, c.old...)
		if now != old {
			t.Errorf("%v and %v run different commands", c.now, c.old)
		}
		if got := cmdID(now); got != c.id {
			t.Errorf("%v: ID %q, want %q", c.now, got, c.id)
		}
		if now.Name() != c.now[len(c.now)-1] || now.Hidden {
			t.Errorf("%v: the new name must be the visible primary (got %q)", c.now, now.Name())
		}
	}
}

// mv is a synonym of rename and prints the same command ID.
func TestRenameMvSynonym(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1")
	mustRun(t, "host", "ssh", "rename", "web1", "web-01")
	if d := mustRun(t, "host", "ssh", "rename", "web-01", "web-02"); d["to"] != "web-02" {
		t.Errorf("host ssh rename: %v", d)
	}
	code, outText := runMain(t, "host", "ssh", "rename", "web-02", "web-03")
	if code != 0 || !strings.Contains(outText, `"command":"host.ssh.rename"`) {
		t.Errorf("host ssh rename: exit %d, %s", code, outText)
	}
}

// `list` is the one listing verb, and `ls` its permanent synonym on every
// list command (S-3.1, OD-2).
func TestStandardListVerb(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
		}
		if c.Hidden || c.Parent() == nil {
			return
		}
		if c.Name() == "ls" {
			t.Errorf("%s: the visible name is list, with ls as an alias", c.CommandPath())
		}
		if c.Name() == "list" && !c.HasAlias("ls") {
			t.Errorf("%s: list needs the ls alias", c.CommandPath())
		}
	}
	walk(newRoot(tcl))
}

// Every noun has its plural and its help word as a synonym (S-2.1), and
// each synonym of C-V07..C-V21 runs the command (and ID) it stands for.
func TestStandardSynonyms(t *testing.T) {
	root := newRoot(tcl)
	for noun, aliases := range nounAliases {
		c := findCmd(t, root, noun)
		for _, a := range aliases {
			if !c.HasAlias(a) {
				t.Errorf("%s: no alias %s", noun, a)
			}
		}
	}
	for _, c := range []struct {
		args []string
		id   string
	}{
		{[]string{"servers"}, "host"}, {[]string{"server", "ssh", "list"}, "host.ssh.list"},
		{[]string{"databases", "postgres", "query"}, "database.postgres.query"}, {[]string{"files", "cat"}, "fs.cat"},
		{[]string{"policies", "list"}, "policy.list"},
		{[]string{"group", "show"}, "group.show"},
		{[]string{"snippet", "show"}, "snippet.show"},
		{[]string{"docker", "describe"}, "docker.inspect"}, {[]string{"registry", "oci", "image", "describe"}, "registry.oci.image.show"},
		{[]string{"db", "user", "create"}, "db.user.add"},
		{[]string{"secret", "copy"}, "secret.cp"},
	} {
		if got := cmdID(findCmd(t, root, c.args...)); got != c.id {
			t.Errorf("%v: ID %q, want %q", c.args, got, c.id)
		}
	}
}

// The wrappers take their own argument rule and give the result of the
// command they stand for; group show and snippet show are commands of their own.
func TestSynonymWrappers(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1", "--group", "web")
	d := mustRun(t, "group", "show", "web")
	if m := d["members"].([]any); len(m) != 1 || m[0] != "web1" {
		t.Errorf("group show web: %v", d)
	}
	wantCode(t, "USAGE", "group", "show")
	if d := mustRun(t, "snippet", "show", "disk"); d["count"].(float64) != 1 {
		t.Errorf("snippet show disk: %v", d)
	}
	wantCode(t, "SNIPPET_NOT_FOUND", "snippet", "show", "nope")
	if code, text := runMain(t, "group", "show", "web"); code != 0 || !strings.Contains(text, `"command":"group.show"`) {
		t.Errorf("group show: exit %d %s", code, text)
	}
}

// `komando schema NAME` describes the command NAME runs: an alias, a
// command ID or a hidden synonym (G-03, S-9.8).
func TestSchemaResolvesNames(t *testing.T) {
	invHome(t)
	for _, c := range []struct {
		args []string
		path string
	}{
		{[]string{"fs.list"}, "komando fs list"},
		{[]string{"fs", "ls"}, "komando fs list"},
		{[]string{"credential", "password", "show"}, "komando credential password show"},
		{[]string{"credential.password.show"}, "komando credential password show"},
		{[]string{"host.ssh.rename"}, "komando host ssh rename"},
		{[]string{"group", "show"}, "komando group show"},
		{[]string{"servers"}, "komando host"},
		{[]string{"db.user.show"}, "komando db user show"},
	} {
		d := mustRun(t, append([]string{"schema"}, c.args...)...)
		cmds := d["commands"].([]any)
		if len(cmds) == 0 || cmds[0].(map[string]any)["path"] != c.path {
			t.Errorf("schema %v: %v", c.args, cmds[:min(len(cmds), 1)])
		}
	}
	wantCode(t, "COMMAND_NOT_FOUND", "schema", "no-such-thing")
	wantCode(t, "COMMAND_NOT_FOUND", "schema", "tunnel", "serve") // komando's own background command
	wantCode(t, "COMMAND_NOT_FOUND", "schema", "db.grants")       // an ID that is gone
}

// `db user show` has the ID db.user.show; `db grants` is no command (C-V15).
func TestDbUserShowReplacesGrants(t *testing.T) {
	invHome(t)
	show := findCmd(t, newRoot(tcl), "db", "user", "show")
	if cmdID(show) != "db.user.show" || show.Hidden {
		t.Fatalf("id %s, hidden %v", cmdID(show), show.Hidden)
	}
	if code, _ := runMain(t, "db", "grants", "nope", "app_ro"); code != out.ExitUsage {
		t.Errorf("db grants: exit %d", code)
	}
	code, text := runMain(t, "db", "user", "show", "nope", "app_ro")
	if code == 0 || !strings.Contains(text, `"command":"db.user.show"`) {
		t.Errorf("db user show: exit %d %s", code, text)
	}
}

// The top-level `forward` (another name for tunnel, which read like
// `cluster kubernetes tunnel start`) is gone (C-V17), and so is `pf` since
// tunnel is `host ssh tunnel` (C6; chief, 2026-11-28: a moved area takes
// no second spelling).
func TestForwardGone(t *testing.T) {
	invHome(t)
	for _, word := range []string{"forward", "pf"} {
		if code, _ := runMain(t, word, "list"); code != out.ExitUsage {
			t.Errorf("%s list: exit %d", word, code)
		}
	}
}
