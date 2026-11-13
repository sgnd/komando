package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// fs replace on a group: each server's change starts with its name, a
// failed one says why, and one server reads as before (no name).
func TestFsFleetText(t *testing.T) {
	one := fsFleetData{Results: []fsChange{{"host": "web1", "ok": true, "path": "/etc/a.conf", "changed": true, "replacements": 1, "backup": "/etc/a.conf.bak"}}}
	if got := one.Text(); !strings.HasPrefix(got, "replaced 1 match(es) in /etc/a.conf\nbackup: /etc/a.conf.bak\n") {
		t.Errorf("one server: %q", got)
	}
	many := fsFleetData{Results: []fsChange{
		{"host": "web1", "ok": true, "path": "/etc/a.conf", "changed": true, "replacements": 1, "backup": "/etc/a.conf.bak"},
		{"host": "web2", "ok": false, "error": out.Errf(out.ExitConflict, "NO_MATCH", "read the file", "--old text not found in /etc/a.conf")},
		{"host": "web3", "ok": true, "path": "/etc/a.conf", "changed": false, "replacements": 0},
	}}
	got := many.Text()
	for _, want := range []string{
		"web1: replaced 1 match(es) in /etc/a.conf\n",
		"web2: failed: --old text not found in /etc/a.conf (NO_MATCH)\n  Hint: read the file\n",
		"web3: no change: /etc/a.conf already has this content\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if n := many.changedWithBackup(); n != 1 {
		t.Errorf("changedWithBackup %d, want 1", n)
	}
}

// The JSON of fs replace and fs restore, on one server or a group: one
// result per server under data.results, and data.summary.
func TestFsFleetJSONShape(t *testing.T) {
	d := fsFleetData{Results: []fsChange{{"host": "web1", "ok": true, "path": "/etc/a.conf", "would_change": true, "replacements": 1, "diff": "-a\n+b\n"}},
		Summary: fleetSummary{Total: 1, OK: 1}}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Results []map[string]any `json:"results"`
		Summary map[string]any   `json:"summary"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	r := v.Results[0]
	if r["host"] != "web1" || r["ok"] != true || r["path"] != "/etc/a.conf" || r["would_change"] != true || v.Summary["total"] != float64(1) {
		t.Errorf("shape: %s", b)
	}
}
