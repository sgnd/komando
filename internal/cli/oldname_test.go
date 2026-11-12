package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestOldNames: every old name is hidden, names a command that exists and
// is not hidden, and has that command's kind (docs/design/ux.md, section 10).
func TestOldNames(t *testing.T) {
	root := newRoot()
	found := map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if now := c.Annotations[oldNameNote]; now != "" {
			found[commandKey(c)] = true
			n, _, err := root.Find(strings.Fields(now))
			switch {
			case !c.Hidden:
				t.Errorf("%s: an old name is hidden", commandKey(c))
			case err != nil || n == c || n.Hidden:
				t.Errorf("%s: says %q, which is not a command", commandKey(c), now)
			case backgroundCmd(c):
				t.Errorf("%s: an old name gets the checks of the new one", commandKey(c))
			}
			if _, ok := kindOf(c); !ok {
				t.Errorf("%s: no kind", commandKey(c))
			}
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	for _, k := range []string{"host import", "host export", "prompt"} {
		if !found[k] {
			t.Errorf("%s is not an old name", k)
		}
	}
}

func TestHostExportIsExport(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1", "-g", "prod")
	mustRun(t, "host", "add", "db1", "u@10.0.0.2")
	d := mustRun(t, "host", "export", "@prod")
	if d["format"] != exportFormat || len(d["hosts"].([]any)) != 1 {
		t.Errorf("host export @prod: %v", d)
	}
	d = mustRun(t, "export", "kind:host")
	if len(d["hosts"].([]any)) != 2 {
		t.Errorf("export kind:host: %v", d)
	}
}

// TestExportTextIsTheFile: -o text prints the export file itself, so there
// is one format to import.
func TestExportTextIsTheFile(t *testing.T) {
	var f exportFile
	if err := json.Unmarshal([]byte(exportFile{Format: exportFormat}.Text()), &f); err != nil || f.Format != exportFormat {
		t.Errorf("text: %v %+v", err, f)
	}
}

// TestDroppedNamesSuggestTheNewOne: a removed old name says which command
// does it now.
func TestDroppedNamesSuggestTheNewOne(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir()) // never the person's own folder
	for _, c := range []struct{ args, want string }{
		{"ops", "recipe"}, {"snippet", "recipe"}, {"snippets", "recipe"}, {"diag", "recipe"},
		{"inspect", "facts"}, {"systemd", "svc"}, {"policy allow", "rm"},
	} {
		if e := usageFor(t, strings.Fields(c.args)...); !strings.HasSuffix(e.Message, "did you mean "+c.want+"?") {
			t.Errorf("%s: %s", c.args, e.Message)
		}
	}
}

// A synonym (a cobra alias such as `x` for exec) is permanent and silent:
// no stderr line and no meta.deprecated.
func TestSynonymsPrintNothing(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	var d map[string]any
	note := stderrOf(t, func() { d = mustRun(t, "--dry-run", "x", "web1", "--", "uptime") })
	if m, _ := d["_meta"].(map[string]any); note != "" || m["deprecated"] != nil {
		t.Errorf("x printed %q, meta %v", note, m)
	}
}

// TestSynonymsGetEveryCheck: a synonym wrapper (cluster info, group show,
// tunnel show, recipe show) is hidden but typed by a person or an agent, so
// it gets every check of the command it names: guardHome and the
// store-writable check do not skip it as a background command, and the
// ssh-gate does not refuse it as plumbing.
func TestSynonymsGetEveryCheck(t *testing.T) {
	n := 0
	for _, c := range allCommands(newRoot()) {
		if c.Annotations[synonymNote] == "" {
			continue
		}
		n++
		if backgroundCmd(c) {
			t.Errorf("%s: a synonym is skipped as a background command", c.CommandPath())
		}
	}
	if n < 4 {
		t.Errorf("found %d synonym wrappers, want at least 4", n)
	}
}
