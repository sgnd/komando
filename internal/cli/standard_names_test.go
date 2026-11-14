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
		{[]string{"host", "rename"}, []string{"host", "mv"}, "host.rename"},
		{[]string{"conn", "rename"}, []string{"conn", "mv"}, "conn.rename"},
		{[]string{"vpn", "rename"}, []string{"vpn", "mv"}, "vpn.rename"},
		{[]string{"key", "rename"}, []string{"key", "mv"}, "key.rename"},
		{[]string{"secret", "rename"}, []string{"secret", "mv"}, "secret.rename"},
		{[]string{"group", "rename"}, []string{"group", "mv"}, "group.rename"},
		{[]string{"secret", "show"}, []string{"secret", "get"}, "secret.show"},
		{[]string{"cluster", "list"}, []string{"cluster", "ls"}, "cluster.list"},
		{[]string{"cluster", "helm", "list"}, []string{"cluster", "helm", "ls"}, "cluster.helm.list"},
		{[]string{"db", "user", "list"}, []string{"db", "user", "ls"}, "db.user.list"},
		{[]string{"fs", "list"}, []string{"fs", "ls"}, "fs.list"},
		{[]string{"queue", "list"}, []string{"queue", "ls"}, "queue.list"},
		{[]string{"registry", "list"}, []string{"registry", "ls"}, "registry.list"},
		{[]string{"storage", "list"}, []string{"storage", "ls"}, "storage.list"},
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
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	mustRun(t, "host", "mv", "web1", "web-01")
	if d := mustRun(t, "host", "rename", "web-01", "web-02"); d["to"] != "web-02" {
		t.Errorf("host rename: %v", d)
	}
	code, outText := runMain(t, "host", "rename", "web-02", "web-03")
	if code != 0 || !strings.Contains(outText, `"command":"host.rename"`) {
		t.Errorf("host rename: exit %d, %s", code, outText)
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
		{[]string{"servers"}, "host"}, {[]string{"server", "list"}, "host.list"},
		{[]string{"databases", "query"}, "db.query"}, {[]string{"files", "cat"}, "fs.cat"},
		{[]string{"tunnels", "list"}, "tunnel.list"}, {[]string{"policies", "list"}, "policy.list"},
		{[]string{"cache", "list"}, "cache.keys"}, {[]string{"cache", "ls"}, "cache.keys"},
		{[]string{"group", "show"}, "group.list"}, {[]string{"job", "show"}, "job.status"},
		{[]string{"tunnel", "show"}, "tunnel.list"}, {[]string{"recipe", "show"}, "recipe.list"},
		{[]string{"policy", "add"}, "policy.deny"}, {[]string{"secret", "add"}, "secret.set"},
		{[]string{"docker", "describe"}, "docker.inspect"}, {[]string{"registry", "describe"}, "registry.inspect"},
		{[]string{"user", "create"}, "user.add"}, {[]string{"db", "user", "create"}, "db.user.add"},
		{[]string{"secret", "copy"}, "secret.cp"}, {[]string{"copy"}, "cp"},
		{[]string{"job", "stop"}, "job.kill"}, {[]string{"secret", "passwd"}, "secret.passphrase"},
		{[]string{"cluster", "info"}, "cluster.status"},
	} {
		if got := cmdID(findCmd(t, root, c.args...)); got != c.id {
			t.Errorf("%v: ID %q, want %q", c.args, got, c.id)
		}
	}
}

// The wrappers take their own argument rule and give the result of the
// command they stand for.
func TestSynonymWrappers(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1", "--group", "web")
	d := mustRun(t, "group", "show", "web")
	if m := d["members"].([]any); len(m) != 1 || m[0] != "web1" {
		t.Errorf("group show web: %v", d)
	}
	wantCode(t, "USAGE", "group", "show")
	if d := mustRun(t, "recipe", "show", "disk"); d["count"].(float64) != 1 {
		t.Errorf("recipe show disk: %v", d)
	}
	wantCode(t, "RECIPE_NOT_FOUND", "recipe", "show", "nope")
	wantCode(t, "TUNNEL_NOT_FOUND", "tunnel", "show", "t-nope")
	if code, text := runMain(t, "group", "show", "web"); code != 0 || !strings.Contains(text, `"command":"group.list"`) {
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
		{[]string{"secret", "get"}, "komando secret show"},
		{[]string{"secret.show"}, "komando secret show"},
		{[]string{"host.rename"}, "komando host rename"},
		{[]string{"group", "show"}, "komando group list"},
		{[]string{"cluster", "info"}, "komando cluster status"},
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
// `cluster forward`) is gone; `pf` stays a synonym (C-V17).
func TestForwardGone(t *testing.T) {
	invHome(t)
	if code, _ := runMain(t, "forward", "list"); code != out.ExitUsage {
		t.Errorf("forward list: exit %d", code)
	}
	if code, text := runMain(t, "pf", "list"); code != 0 || !strings.Contains(text, `"command":"tunnel.list"`) {
		t.Errorf("pf list: exit %d %s", code, text)
	}
}
