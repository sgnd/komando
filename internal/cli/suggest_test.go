package cli

import (
	"slices"
	"strings"
	"testing"
)

// TestUnknownCommandWords: an unknown word gets a foreign word's komando
// command first, else the nearest names by S-5.17's distance (1 for a word
// of 4 letters or fewer, 2 for a longer one), at most two; the hint names a
// command only when there is exactly one (C-E11).
func TestUnknownCommandWords(t *testing.T) {
	root := newRoot(tcl)
	for word, want := range map[string]string{
		"ps": "docker ps TARGET", "get": "list", "kubectl": "cluster kubernetes raw NAME -- ...", "psql": "database postgres query NAME",
		"mysql": "database mysql query NAME", "apt": "pkg", "yum": "pkg", "systemctl": "host ssh exec SERVER -- systemctl",
		"exec": "host ssh exec SERVER -- ...",
	} {
		e := unknownCommandErr(tcl, root, word, nil)
		if e.Suggestion != want || e.Hint != "run `komando "+want+"` instead" || e.Code != "USAGE" {
			t.Errorf("%s: %+v", word, e)
		}
	}
	if e := unknownCommandErr(tcl, root, "delete", []string{"web1"}); e.Suggestion != "host ssh remove web1" {
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
// a list or after =, never after --; the words after -- are not repeated
// (they may hold a password: audit A1).
func TestSwappedLine(t *testing.T) {
	for _, c := range []struct {
		args        []string
		wrong, want string
	}{
		{[]string{"host", "ssh", "exce", "web1", "--", "mysql", "-pS3cret"}, "exce", "komando host ssh exec web1 -- …"},
		{[]string{"host", "ssh", "exec", "web1", "--via", "bast,wbe1"}, "wbe1", "komando host ssh exec web1 --via bast,web1"},
		{[]string{"host", "ssh", "exec", "--limt=5", "web1"}, "--limt", "komando host ssh exec --limit=5 web1"},
		// T4: a leaf that reads a secret's value: no argument is repeated (the
		// value may come first)
		{[]string{"-o", "json", "credentail", "password", "add", "db-pass", "hunter22"}, "credentail", "komando -o json credential password add NAME"},
		{[]string{"credential", "password", "ad", "hunter22", "db-pass"}, "ad", "komando credential password add NAME"},
	} {
		right := map[string]string{"exce": "exec", "wbe1": "web1", "--limt": "--limit", "credentail": "credential", "ad": "add"}[c.wrong]
		if got, ok := swappedLine(c.args, c.wrong, right); !ok || got != c.want {
			t.Errorf("%v: %q", c.args, got)
		}
	}
	if _, ok := swappedLine([]string{"host", "ssh", "exec", "web1", "--", "exce"}, "exce", "exec"); ok {
		t.Error("a word after -- was swapped")
	}
}

// Every command a foreign word suggests exists: its words (up to the first
// placeholder, flag or "...") walk down the command tree to one command.
// A command that is renamed or removed fails here, not in a person's shell.
func TestForeignWordsSuggestRunnableCommands(t *testing.T) {
	root := newRoot(tcl)
	for word, sug := range foreignWords {
		var path []string
		for _, w := range strings.Fields(sug) {
			if w == "--" || w == "..." || strings.HasPrefix(w, "-") || w != strings.ToLower(w) {
				break
			}
			path = append(path, w)
		}
		c, rest, err := root.Find(path)
		if err != nil || c == root || len(rest) != 0 || !(c.Runnable() || c.HasSubCommands()) {
			t.Errorf("%s suggests %q, which is no komando command (found %q, left over %v, %v)", word, sug, c.CommandPath(), rest, err)
		}
	}
}
