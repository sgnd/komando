package cli

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// lineWords finds the command of a command line in the whole command tree
// and reads its words as the safety checks do. These tests pin what it
// answers today, so that building the tree some other way (from the
// capability table, instead of newRoot) cannot change an answer.

func TestLineWordsFindsEveryCommand(t *testing.T) {
	root := newRoot(treeCall())
	n := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			if s.Hidden || !s.Runnable() || strings.HasPrefix(s.Name(), "__") {
				continue
			}
			path := strings.Fields(strings.TrimPrefix(s.CommandPath(), root.Name()+" "))
			got, _, _ := lineWords(path)
			switch {
			case got == nil:
				t.Errorf("lineWords(%q) found no command, want %s", path, s.CommandPath())
			case got.CommandPath() != s.CommandPath():
				t.Errorf("lineWords(%q) found %s, want %s", path, got.CommandPath(), s.CommandPath())
			}
			for _, alias := range s.Aliases {
				apath := append(slices.Clone(path[:len(path)-1]), alias)
				if got, _, _ := lineWords(apath); got == nil || got.CommandPath() != s.CommandPath() {
					t.Errorf("lineWords(%q), the alias of %s, did not find it", apath, s.CommandPath())
				}
			}
			n++
		}
	}
	walk(root)
	if n < 150 {
		t.Fatalf("only %d commands walked", n)
	}
}

func TestLineWordsReadsWordsAndFlags(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		command string
		words   []string
		pos     []string
	}{
		{"positional words", "cache rm c1 k", "komando cache rm", []string{"c1", "k"}, []string{"c1", "k"}},
		{"a flag becomes --name=value", "host edit web1 --protected=false", "komando host edit", []string{"web1", "--protected=false"}, []string{"web1"}},
		{"a bare bool flag becomes =true", "exec web1 --read-only -- df -h", "komando exec", []string{"web1", "--read-only=true", "--", "df", "-h"}, []string{"web1"}},
		{"words after -- are kept apart", "exec web1 -- uptime", "komando exec", []string{"web1", "--", "uptime"}, []string{"web1"}},
		{"an alias finds its command", "host ls", "komando host list", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, words, pos := lineWords(strings.Fields(tt.line))
			if c == nil || c.CommandPath() != tt.command {
				t.Fatalf("lineWords(%q) command = %v, want %s", tt.line, c, tt.command)
			}
			if !slices.Equal(words, tt.words) || !slices.Equal(pos, tt.pos) {
				t.Errorf("lineWords(%q) words %q pos %q, want words %q pos %q", tt.line, words, pos, tt.words, tt.pos)
			}
		})
	}
}

func TestLineWordsNoCommand(t *testing.T) {
	for _, line := range []string{"", "nosuchcommand", "nosuchcommand web1"} {
		if c, words, pos := lineWords(strings.Fields(line)); c != nil || words != nil || pos != nil {
			t.Errorf("lineWords(%q) = %v %q %q, want nothing", line, c, words, pos)
		}
	}
}

func TestLineWordsBadFlagKeepsTheCommand(t *testing.T) {
	c, words, _ := lineWords([]string{"cache", "rm", "c1", "--nosuchflag"})
	if c == nil || c.CommandPath() != "komando cache rm" {
		t.Fatalf("a bad flag lost the command: %v", c)
	}
	if !slices.Contains(words, "--nosuchflag") {
		t.Errorf("the words the run will complain about are gone: %q", words)
	}
}

func TestRiskOfLineEveryCommandHasATier(t *testing.T) {
	root := newRoot(treeCall())
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
			if s.Hidden || !s.Runnable() || strings.HasPrefix(s.Name(), "__") {
				continue
			}
			path := strings.Fields(strings.TrimPrefix(s.CommandPath(), root.Name()+" "))
			got := riskOfLine(path)
			want := riskOf(s, nil)
			if got.tier != want.tier || got.what != want.what || got.dynamic != want.dynamic {
				t.Errorf("riskOfLine(%q) = tier %d, want %d: the line and the command disagree", path, got.tier, want.tier)
			}
		}
	}
	walk(root)
}

var unreachableIDs = map[string]string{
	"komando": "the root has no words: lineWords answers nothing for it, on purpose",
}

// TestLineWordsEveryCommandID: every command ID of today, split into path
// words, goes through lineWords and finds the command with that ID. An ID
// whose command a path cannot reach is named in unreachableIDs with the
// reason.
func TestLineWordsEveryCommandID(t *testing.T) {
	b, err := os.ReadFile("testdata/command_ids.txt")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, id := range strings.Fields(string(b)) {
		if _, ok := unreachableIDs[id]; ok {
			seen[id] = true
			continue
		}
		c, _, _ := lineWords(strings.Split(id, "."))
		switch {
		case c == nil:
			t.Errorf("lineWords(%q) found no command", id)
		case cmdID(c) != id:
			t.Errorf("lineWords(%q) found the command with ID %q", id, cmdID(c))
		}
	}
	for id := range unreachableIDs {
		if !seen[id] {
			t.Errorf("unreachableIDs has %q, which is no command ID: drop it", id)
		}
	}
}

// A repeatable flag gives one word per value, as the person typed it: a
// comma or a double quote in a value does not join it to the next value or
// hide it from a risk word (snippet exec --var is a KEY=VALUE flag).
func TestLineWordsOneWordPerFlagValue(t *testing.T) {
	_, words, _ := lineWords([]string{"snippet", "exec", "dk", "web", "--var", "sub=a,b", "--var", `k="rm`, "--no-sudo"})
	want := []string{"dk", "web", "--no-sudo=true", "--var=sub=a,b", `--var=k="rm`}
	if !slices.Equal(words, want) {
		t.Errorf("words %q, want %q", words, want)
	}
}
