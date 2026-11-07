package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestDocExamplesExist reads every `komando ...` line in the docs, the guide
// and the skill, and checks that the command exists and takes every --flag
// the line uses. A renamed flag or command then fails here, not for a reader.
func TestDocExamplesExist(t *testing.T) {
	files, _ := filepath.Glob("../../docs/features/*.md")
	files = append(files, "../../README.md", "../../AGENTS.md", "../../CONTRIBUTING.md", "../../SECURITY.md", "guide.md", "skill.md")
	root := newRoot()
	line := regexp.MustCompile(`(?:^|[\s(` + "`" + `$])komando ([a-z][^` + "`" + `\n#|;&)]*)`)
	flag := regexp.MustCompile(`(?:^|\s)--([a-z][a-z0-9-]*)`)
	quoted := regexp.MustCompile(`'[^']*'|"[^"]*"`)
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range line.FindAllStringSubmatch(string(b), -1) {
			text := m[1]
			if i := strings.Index(text, " -- "); i >= 0 {
				text = text[:i] // what follows -- belongs to the remote command
			}
			words := strings.Fields(text)
			cmd, rest, err := root.Find(words)
			if err != nil || cmd == root {
				// prose like "komando keeps ..." is not a command line
				if len(words) > 0 && looksLikeCommand(root, words[0]) {
					t.Errorf("%s: `komando %s`: no such command", f, text)
				}
				continue
			}
			// a group command (host, db, ...) takes no words of its own: the first
			// word after it must be one of its subcommands
			if len(rest) > 0 && cmd.HasSubCommands() && !strings.HasPrefix(rest[0], "-") && !strings.HasPrefix(rest[0], "<") {
				t.Errorf("%s: `komando %s`: %s has no subcommand %q", f, strings.TrimSpace(text), cmd.CommandPath(), rest[0])
			}
			checked++
			// flags inside quotes belong to another program (--proxy-command '... --zone x')
			unquoted := quoted.ReplaceAllString(text, "''")
			for _, fm := range flag.FindAllStringSubmatch(" "+unquoted, -1) {
				if !cmdHasFlag(cmd, fm[1]) {
					t.Errorf("%s: `komando %s`: %s has no --%s", f, strings.TrimSpace(text), cmd.CommandPath(), fm[1])
				}
			}
		}
	}
	if checked < 100 {
		t.Errorf("only %d examples found; the scan is broken", checked)
	}
}

// looksLikeCommand: the first word is a top-level command name or alias.
func looksLikeCommand(root *cobra.Command, w string) bool {
	for _, c := range root.Commands() {
		if c.Name() == w || c.HasAlias(w) {
			return true
		}
	}
	return false
}

func cmdHasFlag(c *cobra.Command, name string) bool {
	if name == "help" {
		return true
	}
	for p := c; p != nil; p = p.Parent() {
		if p.Flags().Lookup(name) != nil || p.PersistentFlags().Lookup(name) != nil {
			return true
		}
	}
	return false
}
