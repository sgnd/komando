package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExportKindHost(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1", "-g", "prod")
	mustRun(t, "host", "add", "db1", "u@10.0.0.2")
	d := mustRun(t, "export", "@prod")
	if d["format"] != exportFormat || len(d["hosts"].([]any)) != 1 {
		t.Errorf("export @prod: %v", d)
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

// TestHabitWordsSuggestTheCommand: a word from another tool's habit says
// which command does that job.
func TestHabitWordsSuggestTheCommand(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir()) // never the person's own folder
	for _, c := range []struct{ args, want string }{
		{"inspect", "facts"}, {"systemd", "svc"},
	} {
		if e := usageFor(t, strings.Fields(c.args)...); !strings.HasSuffix(e.Message, "did you mean "+c.want+"?") {
			t.Errorf("%s: %s", c.args, e.Message)
		}
	}
}

// A synonym (a cobra alias such as `x` for exec) is silent: no stderr
// line.
func TestSynonymsPrintNothing(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	if note := stderrOf(t, func() { mustRun(t, "--dry-run", "x", "web1", "--", "uptime") }); note != "" {
		t.Errorf("x printed %q", note)
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
