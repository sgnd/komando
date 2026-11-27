package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/spf13/cobra"
)

// BenchmarkMoveLeaves is the move of the safety tables that init runs once
// per moved type (BenchmarkNewRoot, in root_bench_test.go, is the tree). A
// start that got slower shows in one of the two first.
func BenchmarkMoveLeaves(b *testing.B) {
	types := slices.Clone(movedTypes)
	for b.Loop() {
		b.StopTimer()
		tablesAtStart(func() {
			b.StartTimer()
			for _, typ := range types {
				moveLeaves(typ, capability.All())
			}
			b.StopTimer()
		})
		b.StartTimer() // B.Loop must find the timer running
	}
}

// exampleOf answers from the leaf's own words without Find; it must give
// the answer Find gives, for every example line of every command (a line
// of an alias or of a group still goes to Find).
func TestExampleOfAgreesWithFind(t *testing.T) {
	root := newRoot(tcl)
	lines := 0
	for _, c := range allCommands(root) {
		for _, l := range strings.Split(c.Example, "\n") {
			cmd := strings.TrimSpace(exampleCommand(l))
			if !strings.HasPrefix(cmd, "komando ") || strings.ContainsAny(cmd, "|<>$`;&") {
				continue
			}
			lines++
			found, _, err := root.Find(shellWords(cmd)[1:])
			if want := err == nil && found == c; exampleOf(c, l) != want {
				t.Errorf("%s: exampleOf(%q) = %v, Find says %v", cmdID(c), l, !want, want)
			}
		}
	}
	if lines < 100 {
		t.Errorf("only %d example lines checked", lines)
	}
}

// The step of start that costs the most per command (the profile of
// BenchmarkNewRoot: help standard 67%) skips the work a command does not
// need. Each test holds the short way to the answer of the full way, on the
// whole tree, and that it does less.

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

// exampleTexts are example blocks of every shape the standard looks at; CMD
// is the words of the command they are put on.
var exampleTexts = []string{
	"  komando CMD a b\n  komando CMD a b --dry-run",
	"  komando CMD a b",
	"  komando CMD a b --dry-run\n  komando CMD a b --yes",
	"  komando CMD a b --yes\n  komando CMD c d -y   # a comment",
	"  komando CMD a b --allow-dangerous\n  komando CMD a b --reveal",
	"  komando CMD a b\n  komando CMD a --yes",
	"  komando CMD a --prefix daily/ --allow-dangerous\n  komando CMD a old.txt --dry-run",
	"  komando CMD a old.txt\n  komando CMD a old.txt --allow-dangerous   # after a person's yes",
	"  komando exec web1 -- uptime | head\n  komando CMD a b\n  not a command --yes\n\n  komando CMD x y -- --yes",
	"  komando CMD a b --write\n  komando CMD a b --delete --allow-dangerous",
	"",
}

// firstOfKind is the first runnable command of the tree with examples whose
// kind is one of kinds and whose examples hold no approval flag and begin
// with a line of its own. It is nil when the tree has none.
func firstOfKind(root *cobra.Command, kinds ...string) *cobra.Command {
	for _, c := range allCommands(root) {
		k, ok := kindOf(c)
		if ok && c.HasParent() && c.Runnable() && c.Example != "" && slices.Contains(kinds, k.Kind) && !mayHaveApproval(c.Example) &&
			exampleOf(c, strings.Split(c.Example, "\n")[0]) {
			return c
		}
	}
	return nil
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
	// the texts above on a read and on a change command
	read, change := firstOfKind(root, kindRead), firstOfKind(root, kindChange)
	if read == nil || change == nil {
		t.Fatal("the tree has no read command or no change command with examples")
	}
	for _, c := range []*cobra.Command{read, change} {
		id, was := cmdID(c), c.Example
		for _, ex := range exampleTexts {
			c.Example = strings.ReplaceAll(ex, "CMD", strings.TrimPrefix(c.CommandPath(), "komando "))
			if got, want := standardExamples(c), standardExamplesFull(c); got != want {
				t.Errorf("%s with %q: differs from the full way\n got: %q\nwant: %q", id, c.Example, got, want)
			}
		}
		c.Example = was
	}
}

// A read command whose examples carry no approval flag is not parsed at all.
func TestStandardExamplesLeavesAReadCommandUnparsed(t *testing.T) {
	c := firstOfKind(newRoot(tcl), kindRead)
	if c == nil {
		t.Fatal("the tree has no read command with examples")
	}
	fast := testing.AllocsPerRun(20, func() { standardExamples(c) })
	full := testing.AllocsPerRun(20, func() { standardExamplesFull(c) })
	if fast*3 > full {
		t.Errorf("%s: standardExamples makes %.0f allocations for a read command, the full way %.0f: it should parse nothing", cmdID(c), fast, full)
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
