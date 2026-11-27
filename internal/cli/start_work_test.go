package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The three steps of start that cost the most per command (the profile of
// BenchmarkNewRoot: help standard 67%, completion 12%) skip the work a
// command does not need. Each test holds the short way to the answer of the
// full way, on the whole tree, and that it does less.

// standardExamplesFull is standardExamples before it skipped the lines it
// has nothing to do with: every line parsed, four times over.
func standardExamplesFull(c *cobra.Command) string {
	if c.Example == "" {
		return ""
	}
	lines := strings.Split(c.Example, "\n")
	k, _ := kindOf(c)
	change := k.Kind == kindChange || k.Kind == kindDepends
	hasDry := slices.ContainsFunc(lines, func(l string) bool { return exampleOf(c, l) && slices.Contains(exampleFlags(l), "--dry-run") })
	var out []string
	for _, l := range lines {
		if !exampleOf(c, l) {
			out = append(out, l)
			continue
		}
		flags := exampleFlags(l)
		approval := slices.ContainsFunc(flags, func(f string) bool { return slices.Contains(safetyOverrides, strings.TrimPrefix(f, "--")) || f == "-y" })
		switch {
		case approval:
			dry := dryRunLine(l)
			if len(out) == 0 || strings.Join(strings.Fields(exampleCommand(out[len(out)-1])), " ") != strings.Join(strings.Fields(dry), " ") {
				out = append(out, dry)
			}
			hasDry = true
			if !strings.Contains(l, approvalComment) {
				l = exampleCommand(l) + "   " + approvalComment
			}
		case change && !hasDry && !slices.Contains(flags, "--dry-run") && (k.Kind == kindChange || slices.Contains(flags, "--write")):
			out = append(out, l, dryRunLine(l))
			hasDry = true
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// wrapHelpFull is wrapHelp before its look for a line that is too wide.
func wrapHelpFull(s string, width int) string {
	if s == "" {
		return s
	}
	paras := strings.Split(s, "\n\n")
	for i, p := range paras {
		lines := strings.Split(p, "\n")
		if !slices.ContainsFunc(lines, func(l string) bool { return len([]rune(l)) > width }) {
			continue
		}
		paras[i] = wrapPara(lines, width)
	}
	return strings.Join(paras, "\n\n")
}

// exampleTexts are example blocks of every shape the standard looks at.
var exampleTexts = []string{
	"  komando storage s3 add backups URL\n  komando storage s3 add backups URL --dry-run",
	"  komando storage s3 add backups URL",
	"  komando storage s3 add backups URL --dry-run\n  komando storage s3 add backups URL --yes",
	"  komando storage s3 add backups URL --yes\n  komando storage s3 add other URL -y   # a comment",
	"  komando storage s3 add backups URL --allow-dangerous\n  komando storage s3 add backups URL --reveal",
	"  komando storage s3 object list backups 2026/\n  komando storage s3 object list backups --yes",
	"  komando storage s3 object delete backups --prefix daily/ --allow-dangerous\n  komando storage s3 object delete backups old.txt --dry-run",
	"  komando storage s3 object delete backups old.txt\n  komando storage s3 object delete backups old.txt --allow-dangerous   # after a person's yes",
	"  komando exec web1 -- uptime | head\n  komando storage s3 add backups URL\n  not a command --yes\n\n  komando storage s3 add x URL -- --yes",
	"  komando sync copy a b --write\n  komando sync copy a b --delete --allow-dangerous",
	"",
}

func TestStandardExamplesAgreesWithFullWay(t *testing.T) {
	root := newRoot(tcl)
	checked := 0
	for _, c := range allCommands(root) {
		if got, want := standardExamples(c), standardExamplesFull(c); got != want {
			t.Errorf("%s: standardExamples differs from the full way\n got: %q\nwant: %q", cmdID(c), got, want)
		}
		checked++
	}
	if checked < 300 {
		t.Fatalf("only %d commands checked", checked)
	}
	// the same commands with the texts above: a read, a change and a dangerous one
	for _, id := range []string{"storage.s3.object.list", "storage.s3.add", "storage.s3.object.delete", "exec"} {
		c := commandWithID(root, id)
		if c == nil {
			t.Fatalf("no command %s", id)
		}
		was := c.Example
		for _, ex := range exampleTexts {
			c.Example = ex
			if got, want := standardExamples(c), standardExamplesFull(c); got != want {
				t.Errorf("%s with %q: differs from the full way\n got: %q\nwant: %q", id, ex, got, want)
			}
		}
		c.Example = was
	}
}

// A read command whose examples carry no approval flag is not parsed at all.
func TestStandardExamplesLeavesAReadCommandUnparsed(t *testing.T) {
	root := newRoot(tcl)
	c := commandWithID(root, "storage.s3.object.list")
	if c == nil || c.Example == "" {
		t.Fatal("storage s3 object list has no example")
	}
	fast := testing.AllocsPerRun(20, func() { standardExamples(c) })
	full := testing.AllocsPerRun(20, func() { standardExamplesFull(c) })
	if fast*3 > full {
		t.Errorf("standardExamples makes %.0f allocations for a read command, the full way %.0f: it should parse nothing", fast, full)
	}
}

func TestWrapHelpAgreesWithFullWay(t *testing.T) {
	root := newRoot(tcl)
	long := strings.Repeat("word ", 30)
	texts := []string{"", "short", "a\n\nb", long, "first " + long + "\n\n- item " + long + "\n  indented line\n\nlast", "é" + strings.Repeat("é", 80)}
	for _, c := range allCommands(root) {
		texts = append(texts, c.Long)
	}
	for _, s := range texts {
		if got, want := wrapHelp(s, helpWidth), wrapHelpFull(s, helpWidth); got != want {
			t.Errorf("wrapHelp(%q) differs from the full way\n got: %q\nwant: %q", s, got, want)
		}
	}
	short := "one line\n\nand another"
	if a := testing.AllocsPerRun(20, func() { wrapHelp(short, helpWidth) }); a != 0 {
		t.Errorf("wrapHelp of text with no wide line makes %.0f allocations, want 0", a)
	}
}

// flagCompletion asks a command that has no such flag without copying all
// its flags (LocalFlags), and gives the answer LocalFlags gives.
func TestFlagCompletionSkipsACommandWithoutTheFlag(t *testing.T) {
	root := newRoot(tcl)
	for _, c := range allCommands(root) {
		for _, name := range []string{"key", "via", "target"} {
			declared := c.Flags().Lookup(name) != nil || c.PersistentFlags().Lookup(name) != nil
			if local := c.LocalFlags().Lookup(name) != nil; local && !declared {
				t.Errorf("%s: --%s is local but flagCompletion's first look does not see it", cmdID(c), name)
			}
		}
	}
	// LocalFlags merges the parents' persistent flags into the command's
	// flag set, once per command: a command with no --key is left unmerged.
	parent := &cobra.Command{Use: "komando"}
	parent.PersistentFlags().String("output", "", "")
	plain := &cobra.Command{Use: "plain"}
	plain.Flags().String("name", "", "")
	withKey := &cobra.Command{Use: "withkey"}
	withKey.Flags().String("key", "", "")
	parent.AddCommand(plain, withKey)
	none := func(string) []string { return nil }
	flagCompletion(plain, "key", none)
	flagCompletion(withKey, "key", none)
	if plain.Flags().Lookup("output") != nil {
		t.Error("flagCompletion merged the parent's flags into a command with no --key")
	}
}
