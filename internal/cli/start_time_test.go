package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
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
	if checked < 280 {
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

// The tree of one line (newRootFor) prepares the command the line names as
// the whole tree (newRoot) does: for every command, hidden ones too, what
// runs, what the gate reads, the audit name, the completion and the help
// are the same, byte for byte.
func TestLineTreeAgreesWithWholeTree(t *testing.T) {
	whole := newRoot(tcl)
	checked := 0
	for _, c := range allCommands(whole)[1:] {
		line := strings.Fields(c.CommandPath())[1:]
		lc, _, err := newRootFor(tcl, line).Find(line)
		if err != nil || lc.CommandPath() != c.CommandPath() {
			t.Errorf("%s: the line tree finds %q (%v)", cmdID(c), lc.CommandPath(), err)
			continue
		}
		if got, want := nodeFacts(lc), nodeFacts(c); got != want {
			t.Errorf("%s: the line tree differs from the whole tree\n got: %s\nwant: %s", cmdID(c), got, want)
		}
		checked++
	}
	if checked < 300 {
		t.Errorf("only %d commands checked", checked)
	}
}

// nodeFacts is what a run of c reads from the tree, as text to compare.
func nodeFacts(c *cobra.Command) string {
	var b strings.Builder
	fmt.Fprintf(&b, "id %s, envelope %s, name %s\n", cmdID(c), envelopeName(c), commandName(c))
	fmt.Fprintf(&b, "use %q short %q aliases %q suggest %q group %q hidden %v deprecated %q runnable %v\n",
		c.Use, c.Short, c.Aliases, c.SuggestFor, c.GroupID, c.Hidden, c.Deprecated, c.Runnable())
	fmt.Fprintf(&b, "long %q\nexample %q\nannotations %v\n", c.Long, c.Example, c.Annotations)
	fmt.Fprintf(&b, "hooks: pre %v, run %v, persistent pre %v, valid args %v\n",
		c.PreRunE != nil || c.PreRun != nil, c.RunE != nil || c.Run != nil, c.PersistentPreRunE != nil, c.ValidArgsFunction != nil)
	for _, args := range [][]string{nil, {"a"}, {"a", "b"}, {"a", "b", "c"}} {
		fmt.Fprintf(&b, "args %q: %v\n", args, c.ValidateArgs(args))
	}
	k, ok := kindOf(c)
	fmt.Fprintf(&b, "kind %v %v, person only %v\n", k, ok, personOnly(c))
	if ok {
		fmt.Fprintf(&b, "confirm %v, safety %q\n", confirmOf(c), safetyLine(c))
	}
	for _, r := range rowsFor(c) {
		fmt.Fprintf(&b, "row %v %q %v %q %q %q %q %q when %v\n", r.key, r.cond, r.tier, r.what, r.dynamic, r.bulk, r.typed, r.items, r.when != nil)
	}
	flags := func(fs *pflag.FlagSet) {
		fs.VisitAll(func(f *pflag.Flag) {
			_, complete := c.GetFlagCompletionFunc(f.Name)
			fmt.Fprintf(&b, "flag --%s -%s %s %q %q %q hidden %v %v completes %v\n",
				f.Name, f.Shorthand, f.Value.Type(), f.DefValue, f.NoOptDefVal, f.Usage, f.Hidden, f.Annotations, complete)
		})
	}
	flags(c.LocalFlags())
	flags(c.InheritedFlags())
	for _, s := range c.Commands() {
		fmt.Fprintf(&b, "sub %s %q %q hidden %v available %v\n", s.Name(), s.Short, s.Aliases, s.Hidden, s.IsAvailableCommand())
	}
	var help bytes.Buffer
	c.SetOut(&help)
	defer c.SetOut(nil)
	_ = c.Help()
	b.WriteString(help.String())
	return b.String()
}

// Every way into komando prepares the command it runs: the line, the
// shell's completion, global flags before the command.
func TestEntryPointsPrepareTheirCommand(t *testing.T) {
	for _, tc := range []struct {
		line []string
		want string // the command's path that must be prepared
	}{
		{[]string{"host", "ssh", "list"}, "host ssh list"},
		{[]string{"-o", "json", "--timeout", "5s", "host", "ssh", "list", "web1"}, "host ssh list"},
		{[]string{"host", "ssh", "ls"}, "host ssh list"},
		{[]string{cobra.ShellCompRequestCmd, "host", "li"}, "host"},
		{[]string{cobra.ShellCompNoDescRequestCmd, "host", "ssh", "list", ""}, "host ssh list"},
		{[]string{"-o", "json", cobra.ShellCompRequestCmd, "host", "ssh", "remove"}, "host ssh remove"},
		{[]string{"host", "lst"}, "host"},
		{[]string{"nosuchword"}, ""},
		{nil, ""},
	} {
		root := newRootFor(tcl, tc.line)
		c, _, err := root.Find(strings.Fields(tc.want))
		if err != nil || !prepared(c) {
			t.Errorf("%q: %q is not prepared", tc.line, tc.want)
		}
		for _, s := range c.Commands() {
			if !inList(s) {
				t.Errorf("%q: %q, which the help of %q lists, is not ready to list", tc.line, s.CommandPath(), tc.want)
			}
		}
	}
}

// A script's `LINE --help` prints the command's help as the whole tree has
// it, Safety line and all (the e2e core checks of base.sh).
func TestScriptHelpShowsTheSafetyLine(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	env := map[string]string{"KOMANDO_HOME": home, "USER": "ana"}
	cases := []struct {
		cmd, tier string // tier: words of its Safety line, "" for a read
	}{
		{"host ssh list", ""},
		{"host ssh remove", "a change"},
		{"credential password remove", "dangerous"},
	}
	// the runs first: a whole tree built before them could hide a step
	// that only the whole tree takes
	printed := map[string][2]string{}
	for _, tc := range cases {
		args := slices.Concat(strings.Fields(tc.cmd), []string{"--help", "-o", "text"})
		var o, e bytes.Buffer
		ec := engine.Call{Program: "komando", LookupEnv: envOf(env, &sync.Map{}), Stdout: &o, Stderr: &e}
		if code := RunCall(context.Background(), ec, args); code != 0 {
			t.Errorf("%q: exit %d, stderr %q", args, code, e.String())
		}
		printed[strings.Join(args, " ")] = [2]string{o.String(), e.String()}
	}
	whole := newRoot(tcl)
	for _, tc := range cases {
		c, _, err := whole.Find(strings.Fields(tc.cmd))
		if err != nil || c.CommandPath() != "komando "+tc.cmd {
			t.Fatalf("%s: the whole tree finds %q (%v)", tc.cmd, c.CommandPath(), err)
		}
		if line := safetyLine(c); !strings.Contains(line, tc.tier) || (tc.tier == "") != (line == "") {
			t.Fatalf("%s: the Safety line is %q, want one with %q", tc.cmd, line, tc.tier)
		}
		args := tc.cmd + " --help -o text"
		o, e := printed[args][0], printed[args][1]
		if !strings.Contains(o, c.Long) || strings.Contains(o, "Safety: ") != (tc.tier != "") {
			t.Errorf("%q: stdout lacks the help of the whole tree\n got: %q\nwant: %q\nstderr: %q", args, o, c.Long, e)
		}
	}
}

// The trees the guard (commandTree) and the ssh gate read prepare the
// command of their line too; the gate's tree, asked line after line, each.
func TestReadTreesPrepareTheirCommand(t *testing.T) {
	sc, gate := gateTree()
	for _, line := range [][]string{{"host", "ssh", "list"}, {"-o", "json", "database", "postgres", "query", "x", "select 1"}, {"queue", "kafka", "topic", "delete", "q1", "t"}, {"host", "ssh", "ls"}} {
		if c, _, err := commandTree(line).Find(line); err != nil || !prepared(c) || !c.HasParent() {
			t.Errorf("%q: the guard's tree finds %q, not prepared (%v)", line, c.CommandPath(), err)
		}
		gateCheckIn(sc, gate, slices.Clone(line), gateKey{})
		if c, _, err := gate.Find(line); err != nil || !prepared(c) || !c.HasParent() {
			t.Errorf("%q: the gate's tree finds %q, not prepared (%v)", line, c.CommandPath(), err)
		}
	}
}

// A command the tree did not prepare runs nothing: the root refuses it
// with an internal error before any check or handler.
func TestUnpreparedCommandRunsNothing(t *testing.T) {
	ran := false
	l := capability.Leaf{Key: capability.Key{Type: "zzlazy", Verb: "run"}, State: capability.Built, Short: "Runs in a test"}
	withTable(t, []capability.Leaf{l}, map[capability.Key]handler{l.Key: func(*call, context.Context, leafInput) error { ran = true; return nil }},
		map[string]string{"zzlazy": "A type of a test"})
	for _, prepare := range [][]string{{"version"}, {"zzlazy"}} {
		root := newRootFor(tcl, prepare)
		root.SetArgs([]string{"zzlazy", "run"})
		_, err := root.ExecuteC()
		var oe *out.Error
		if !errors.As(err, &oe) || oe.Code != "PREPARE_FAILED" || oe.Exit != out.ExitError {
			t.Errorf("prepared for %q, zzlazy run gives %v, want PREPARE_FAILED", prepare, err)
		}
		if ran {
			t.Fatalf("prepared for %q, the handler of zzlazy run ran", prepare)
		}
	}
	if c, _, err := newRoot(tcl).Find([]string{"zzlazy", "run"}); err != nil || !prepared(c) {
		t.Error("the whole tree does not prepare zzlazy run")
	}
	// status --short skips the root's hook: its own refuses it as well
	root := newRootFor(tcl, []string{"version"})
	root.SetArgs([]string{"status", "--short"})
	_, err := root.ExecuteC()
	if oe := (*out.Error)(nil); !errors.As(err, &oe) || oe.Code != "PREPARE_FAILED" {
		t.Errorf("prepared for version, status --short gives %v, want PREPARE_FAILED", err)
	}
}

// fakeLeaves are n built leaves of a type nobody names in a line.
func fakeLeaves(t testing.TB, n int) {
	t.Helper()
	var leaves []capability.Leaf
	hs := map[capability.Key]handler{}
	for i := range n {
		l := capability.Leaf{Key: capability.Key{Type: "zzfake", Area: fmt.Sprintf("a%02d", i/20), Verb: fmt.Sprintf("v%03d", i)}, State: capability.Built, Short: "A fake leaf",
			Options: []capability.Option{{Name: "fake-flag", Kind: capability.String, Help: "a flag"}}}
		leaves = append(leaves, l)
		hs[l.Key] = func(*call, context.Context, leafInput) error { return nil }
	}
	groups := map[string]string{"zzfake": "Fake leaves of a test"}
	for i := range n / 20 {
		groups[fmt.Sprintf("zzfake a%02d", i)] = "A fake area"
	}
	withTable(t, leaves, hs, groups)
}

// Start does not grow with the commands of a type the line does not name:
// with 500 more leaves the tree of `komando version` has their 500 nodes,
// but prepares the same commands and lists one more (their type's word).
func TestStartFlatWithMoreLeaves(t *testing.T) {
	line := []string{"version"}
	ready := func(root *cobra.Command) (nodes, prep, list int) {
		for _, c := range allCommands(root) {
			nodes++
			if prepared(c) {
				prep++
			} else if inList(c) {
				list++
			}
		}
		return nodes, prep, list
	}
	work := func() (line, whole float64) {
		return testing.AllocsPerRun(5, func() { newRootFor(tcl, []string{"version"}) }), testing.AllocsPerRun(5, func() { newRoot(tcl) })
	}
	nodes, prep, list := ready(newRootFor(tcl, line))
	lineAllocs, wholeAllocs := work()
	fakeLeaves(t, 500)
	moreNodes, morePrep, moreList := ready(newRootFor(tcl, line))
	if moreNodes < nodes+500 {
		t.Fatalf("the tree has %d commands with the fake leaves, want at least %d", moreNodes, nodes+500)
	}
	if morePrep != prep || moreList != list+1 {
		t.Errorf("500 leaves of another type: %d prepared and %d listed for version, want %d and %d (their type's word only)", morePrep, moreList, prep, list+1)
	}
	moreLine, moreWhole := work()
	// their nodes cost allocations; preparing them costs more, and only
	// the whole tree pays that
	if grew, wholeGrew := moreLine-lineAllocs, moreWhole-wholeAllocs; grew*2 > wholeGrew {
		t.Errorf("500 leaves of another type: the tree of version grew by %.0f allocations, the whole tree by %.0f: want under half", grew, wholeGrew)
	} else {
		t.Logf("500 leaves of another type: the tree of version grew by %.0f allocations, the whole tree by %.0f", grew, wholeGrew)
	}
}

// mountLeaves reads every ID of today's tree once per start, before any
// command has its ID stamped: one string per command, the same IDs cmdID
// gives (a withID annotation wins).
func TestIdsInTreeAgreesWithCmdIDAtOneStringEach(t *testing.T) {
	root := &cobra.Command{Use: "komando"}
	for g := range 5 {
		group := &cobra.Command{Use: fmt.Sprintf("group%d", g)}
		root.AddCommand(group)
		for a := range 5 {
			area := &cobra.Command{Use: fmt.Sprintf("area%d", a)}
			group.AddCommand(area)
			for v := range 5 {
				area.AddCommand(&cobra.Command{Use: fmt.Sprintf("verb%d ARG", v)})
			}
		}
	}
	withID(root.Commands()[0].Commands()[0], "wrapped.id")
	want := map[string]bool{}
	cmds := allCommands(root)[1:]
	for _, c := range cmds {
		want[cmdID(c)] = true
	}
	if got := idsInTree(root); !maps.Equal(got, want) {
		t.Fatalf("idsInTree has %d IDs, cmdID of every command %d: they differ", len(got), len(want))
	}
	if n := testing.AllocsPerRun(5, func() { idsInTree(root) }); n > float64(2*len(cmds)) {
		t.Errorf("idsInTree: %.0f allocations for %d commands, want at most two each", n, len(cmds))
	}
}
