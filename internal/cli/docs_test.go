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
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checked += checkExampleLines(t, root, f, string(b))
	}
	if checked < 100 {
		t.Errorf("only %d examples found; the scan is broken", checked)
	}
}

// TestHelpExamplesExist does the same for the Example text of every command,
// which `komando CMD --help` shows. A wrong flag there misleads people and
// agents just as much as one in the docs.
func TestHelpExamplesExist(t *testing.T) {
	root := newRoot()
	checked := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Example != "" {
			checked += checkExampleLines(t, root, "`"+c.CommandPath()+"` Example", c.Example)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	if checked < 50 {
		t.Errorf("only %d help examples found; the scan is broken", checked)
	}
}

var (
	exampleLine   = regexp.MustCompile(`(?:^|[\s(` + "`" + `$])komando ([a-z][^` + "`" + `\n#|;&)]*)`)
	exampleFlag   = regexp.MustCompile(`(?:^|\s)--([a-z][a-z0-9-]*)`)
	exampleQuoted = regexp.MustCompile(`'[^']*'|"[^"]*"`)
)

// checkExampleLines checks every `komando ...` line in text: the command
// exists, a group command is followed by one of its subcommands, and every
// --flag is one the command takes. It returns how many lines it checked.
func checkExampleLines(t *testing.T, root *cobra.Command, source, text string) int {
	t.Helper()
	checked := 0
	for _, m := range exampleLine.FindAllStringSubmatch(text, -1) {
		line := m[1]
		if i := strings.Index(line, " -- "); i >= 0 {
			line = line[:i] // what follows -- belongs to the remote command
		}
		words := strings.Fields(line)
		cmd, rest, err := root.Find(words)
		if err != nil || cmd == root {
			// prose like "komando keeps ..." is not a command line
			if len(words) > 0 && looksLikeCommand(root, words[0]) {
				t.Errorf("%s: `komando %s`: no such command", source, line)
			}
			continue
		}
		// a group command (host, db, ...) takes no words of its own: the first
		// word after it must be one of its subcommands (login takes a HOST too)
		ownWords := cmd.Runnable() && cmd.Args != nil
		if len(rest) > 0 && cmd.HasSubCommands() && !ownWords && !strings.HasPrefix(rest[0], "-") && !strings.HasPrefix(rest[0], "<") {
			t.Errorf("%s: `komando %s`: %s has no subcommand %q", source, strings.TrimSpace(line), cmd.CommandPath(), rest[0])
		}
		checked++
		// flags inside quotes belong to another program (--proxy-command '... --zone x')
		unquoted := exampleQuoted.ReplaceAllString(line, "''")
		for _, fm := range exampleFlag.FindAllStringSubmatch(" "+unquoted, -1) {
			if !cmdHasFlag(cmd, fm[1]) {
				t.Errorf("%s: `komando %s`: %s has no --%s", source, strings.TrimSpace(line), cmd.CommandPath(), fm[1])
			}
		}
	}
	return checked
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
