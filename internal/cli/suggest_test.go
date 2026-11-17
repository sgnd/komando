package cli

import (
	"slices"
	"testing"
)

// TestUnknownCommandWords: an unknown word gets a foreign word's komando
// command first, else the nearest names by S-5.17's distance (1 for a word
// of 4 letters or fewer, 2 for a longer one), at most two; the hint names a
// command only when there is exactly one (C-E11).
func TestUnknownCommandWords(t *testing.T) {
	root := newRoot(tcl)
	for word, want := range map[string]string{
		"ps": "docker ps TARGET", "get": "list", "kubectl": "cluster run TARGET -- ...", "psql": "db query CONN",
		"mysql": "db query CONN", "apt": "pkg", "yum": "pkg", "systemctl": "svc",
	} {
		e := unknownCommandErr(tcl, root, word, nil)
		if e.Suggestion != want || e.Hint != "run `komando "+want+"` instead" || e.Code != "USAGE" {
			t.Errorf("%s: %+v", word, e)
		}
	}
	if e := unknownCommandErr(tcl, root, "delete", []string{"web1"}); e.Suggestion != "host rm web1" {
		t.Errorf("delete web1: %+v", e)
	}
	if e := unknownCommandErr(tcl, root, "delete", []string{"conn", "pg"}); e.Suggestion != "conn rm pg" {
		t.Errorf("delete conn pg: %+v", e)
	}
	// a short word: distance 1 only, so `ps` never matched cp, db, fs, pkg
	// and vpn, nor `lst` fs and host
	if got := nearWords("lst", commandNames(root)); !slices.Equal(got, []string{"list"}) {
		t.Errorf("lst: %v", got)
	}
	if got := nearWords("zzzz", commandNames(root)); len(got) != 0 {
		t.Errorf("zzzz: %v", got)
	}
	if got := nearWords("stauts", commandNames(root)); !slices.Equal(got, []string{"status"}) {
		t.Errorf("stauts: %v", got)
	}
	// two near names: both in the message, no command in the hint
	if got := nearWords("cash", []string{"cache", "cast", "cask"}); len(got) != 2 {
		t.Errorf("at most two: %v", got)
	}
	e := unknownCommandErr(tcl, root, "logz", nil)
	if e.Suggestion != "logs" {
		t.Errorf("logz: %+v", e)
	}
}

// TestSwappedLine: the suggested word replaces the wrong one, also inside
// a list or after =, never after --.
func TestSwappedLine(t *testing.T) {
	for _, c := range []struct {
		args        []string
		wrong, want string
	}{
		{[]string{"exce", "web1", "--", "uptime"}, "exce", "komando exec web1 -- uptime"},
		{[]string{"exec", "web1", "--via", "bast,wbe1"}, "wbe1", "komando exec web1 --via bast,web1"},
		{[]string{"exec", "--limt=5", "web1"}, "--limt", "komando exec --limit=5 web1"},
	} {
		right := map[string]string{"exce": "exec", "wbe1": "web1", "--limt": "--limit"}[c.wrong]
		if got, ok := swappedLine(c.args, c.wrong, right); !ok || got != c.want {
			t.Errorf("%v: %q", c.args, got)
		}
	}
	if _, ok := swappedLine([]string{"exec", "web1", "--", "exce"}, "exce", "exec"); ok {
		t.Error("a word after -- was swapped")
	}
}
