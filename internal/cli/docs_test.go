package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// TestErrorCodesDoc keeps docs/features/error-codes.md, the table of every
// error code, the same as the catalog in errcodes.go. Rewrite it with
// KOMANDO_UPDATE_ERRCODES=1 go test ./internal/cli/ -run TestErrorCodesDoc
func TestErrorCodesDoc(t *testing.T) {
	cell := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ")
	}
	var b strings.Builder
	b.WriteString("# Error codes\n\n")
	b.WriteString("Every error code komando gives, with its exit code, an example message and\n")
	b.WriteString("the usual next step. The error's own `hint` says what to do in your case.\n")
	b.WriteString("This page is made from the code (`komando schema` lists the same under\n")
	b.WriteString("`error_codes`). [Results and errors](output.md) explains the common ones.\n")
	b.WriteString("[All docs](README.md)\n\n")
	b.WriteString("| Code | Exit | Example message | Usual next step |\n")
	b.WriteString("|------|------|-----------------|-----------------|\n")
	for _, c := range errorCodes {
		fmt.Fprintf(&b, "| `%s` | %d | %s | %s |\n", c.Code, c.Exit, cell(c.Example), cell(c.Hint))
	}
	b.WriteString("\n## Codes shared by several things\n\n")
	b.WriteString("These codes are given for more than one kind of item. `error.thing` says\n")
	b.WriteString("which one (it is left out for the other codes). A later contract gives\n")
	b.WriteString("each its own code; until then the code stays as it is.\n\n")
	b.WriteString("| Code | `error.thing` | Codes it will split into |\n")
	b.WriteString("|------|---------------|--------------------------|\n")
	for _, c := range sharedCodes {
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", c.Code, "`"+strings.Join(c.Things, "`, `")+"`", c.Split)
	}
	b.WriteString("\n## Codes that mean the same\n\n")
	b.WriteString("Each row is codes that mean the same thing. All of them stay, since\n")
	b.WriteString("scripts branch on them; new errors use the first one, and a later\n")
	b.WriteString("contract keeps only that one.\n\n")
	b.WriteString("| Codes | Use | Meaning |\n")
	b.WriteString("|-------|-----|---------|\n")
	for _, c := range sameAsCodes {
		fmt.Fprintf(&b, "| %s | `%s` | %s |\n", "`"+strings.Join(c.Codes, "`, `")+"`", c.Survivor, cell(c.Note))
	}
	const path = "../../docs/features/error-codes.md"
	if os.Getenv("KOMANDO_UPDATE_ERRCODES") != "" {
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != b.String() {
		t.Error("docs/features/error-codes.md is out of date: run KOMANDO_UPDATE_ERRCODES=1 go test ./internal/cli/ -run TestErrorCodesDoc")
	}
}

// TestDocsExit6Codes: the agent rules (AGENTS.md, the skill, the guide) list
// every exit-6 code, and only those, so an agent knows each safety stop.
func TestDocsExit6Codes(t *testing.T) {
	var want []string
	for _, c := range errorCodes {
		if c.Exit == 6 {
			want = append(want, c.Code)
		}
	}
	slices.Sort(want)
	codeWord := regexp.MustCompile(`[A-Z][A-Z0-9_]*[A-Z0-9]`)
	for file, marks := range map[string][2]string{
		"../../AGENTS.md": {"(exit 6: ", ")"},
		"skill.md":        {"(exit 6: ", ")"},
		"guide.md":        {"| 6    | ", " |"},
	} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		i := strings.Index(s, marks[0])
		if i < 0 {
			t.Errorf("%s: no %q list", file, marks[0])
			continue
		}
		s = s[i+len(marks[0]):]
		s = s[:strings.Index(s, marks[1])]
		got := codeWord.FindAllString(s, -1)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s lists the exit-6 codes %v; the catalog has %v", file, got, want)
		}
	}
}
