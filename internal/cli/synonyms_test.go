package cli

import (
	"encoding/json"
	"testing"
)

func TestExportKindHost(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1", "-g", "prod")
	mustRun(t, "host", "ssh", "add", "db1", "u@10.0.0.2")
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

// A synonym (a cobra alias such as `x` for exec) is silent: no stderr
// line.
func TestSynonymsPrintNothing(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1")
	if note := stderrOf(t, func() { mustRun(t, "host", "ssh", "ls") }); note != "" {
		t.Errorf("ls printed %q", note)
	}
}
