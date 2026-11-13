package cli

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// The parts of every command's help that come from one table, so they
// cannot drift from what the command does (S-6.4, S-6.5, S-6.7):
//   - a person-only command's Short ends with "(person only)", from the
//     rule table's T4 rows;
//   - a change command's Long has a "Safety:" line after its first
//     paragraph, from the same rows `komando schema` shows as confirm;
//   - Long is wrapped at 76 columns;
//   - a change command shows a --dry-run example, and an example with
//     --yes, --allow-dangerous or --reveal comes right after its dry run
//     and ends with "# after a person's yes".

// helpWidth is the widest a Long line may be (S-6.5).
const helpWidth = 76

// personOnlyMark ends a person-only command's Short (S-6.4).
const personOnlyMark = "(person only)"

// approvalComment ends an example line with an approval flag (S-6.7).
const approvalComment = "# after a person's yes"

// applyHelpStandard writes the generated parts into c and its
// sub-commands. It runs after stampIDs, when every command has its ID.
func applyHelpStandard(c *cobra.Command) {
	for _, sub := range c.Commands() {
		applyHelpStandard(sub)
	}
	if !c.Runnable() || !c.HasParent() {
		return
	}
	if personOnly(c) && !strings.HasSuffix(c.Short, personOnlyMark) {
		c.Short += " " + personOnlyMark
	}
	if line := safetyLine(c); line != "" && !strings.Contains(c.Long, "Safety: ") {
		c.Long = withSafety(c.Long, c.Short, line)
	}
	c.Long = wrapHelp(c.Long, helpWidth)
	c.Example = standardExamples(c)
}

// personOnly: only a person at a terminal can run c, whatever its words.
func personOnly(c *cobra.Command) bool {
	id := cmdID(c)
	return slices.ContainsFunc(riskRows, func(r riskRow) bool { return r.id == id && r.tier == tierPerson && r.when == nil })
}

// safetyLine is the "Safety:" line of c's Long, from its rule rows
// (confirmOf), or "" for a command that only reads.
func safetyLine(c *cobra.Command) string {
	k, ok := kindOf(c)
	if !ok {
		return ""
	}
	conf := confirmOf(c)
	if k.Kind == kindRead && len(conf) == 1 && conf[0].Tier == tierRead.String() {
		return ""
	}
	var parts []string
	for i, e := range conf {
		s := tierWords(e.Tier)
		if i > 0 || e.When != "" {
			s = e.When + ": " + s
		}
		parts = append(parts, s)
	}
	if conf[0].Tier != tierPerson.String() && actsOnTargets(c) {
		parts = append(parts, "on a protected server or conn, a person's yes (--yes) as well")
	}
	return "Safety: " + strings.Join(parts, "; ") + "."
}

// tierWords is what a tier asks for, in the words of the Safety line.
func tierWords(t string) string {
	switch t {
	case tierRead.String():
		return "it only reads"
	case tierChange.String():
		return "a change; try it with --dry-run first"
	case tierDangerous.String():
		return "dangerous, it cannot be undone: a person types the name to go on, and an AI agent or a script needs --allow-dangerous"
	case tierSafety.String():
		return "it weakens a safety check: a person's yes (--yes)"
	case tierPerson.String():
		return "only a person at a terminal can run it"
	}
	return t
}

// actsOnTargets: c's Use names where it acts (TARGET, SERVER or CONN), so
// a protected target asks for --yes.
func actsOnTargets(c *cobra.Command) bool {
	for _, w := range strings.Fields(c.Use) {
		for _, alt := range strings.Split(strings.Trim(strings.TrimSuffix(strings.Trim(w, "[]"), "..."), "[]"), "|") {
			if gateTargetWords[alt] {
				return true
			}
		}
	}
	return false
}

// withSafety puts line after the first paragraph of long (S-6.5): what
// the command does, then the Safety line, then the notes. An empty long
// starts with the Short as a sentence.
func withSafety(long, short, line string) string {
	if strings.TrimSpace(long) == "" {
		s := strings.TrimSuffix(strings.TrimSuffix(short, " "+personOnlyMark), ".")
		return s + ".\n\n" + line
	}
	first, rest, ok := strings.Cut(long, "\n\n")
	if !ok {
		return long + "\n\n" + line
	}
	return first + "\n\n" + line + "\n\n" + rest
}

// wrapHelp wraps the paragraphs of s at width: a plain paragraph is
// filled again, a list item ("- ...") keeps two spaces in front of its
// later lines, and indented lines (examples, tables) stay as written.
func wrapHelp(s string, width int) string {
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

// wrapPara fills one paragraph, item by item.
func wrapPara(lines []string, width int) string {
	var out []string
	var item []string
	indent := ""
	flush := func() {
		if len(item) > 0 {
			out = append(out, fillWords(strings.Join(item, " "), width, indent)...)
		}
		item, indent = nil, ""
	}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "- "), strings.HasPrefix(l, "* "):
			flush()
			item, indent = []string{l}, "  "
		case strings.HasPrefix(l, "  ") && indent == "":
			flush()
			out = append(out, l) // an indented line: an example or a table row
		default:
			item = append(item, strings.TrimSpace(l))
		}
	}
	flush()
	return strings.Join(out, "\n")
}

// fillWords breaks text into lines of at most width runes; later lines start
// with indent. A word longer than a line stays whole.
func fillWords(text string, width int, indent string) []string {
	var lines []string
	cur := ""
	for _, w := range strings.Fields(text) {
		switch {
		case cur == "":
			cur = w
			if len(lines) > 0 {
				cur = indent + w
			}
		case len([]rune(cur))+1+len([]rune(w)) <= width:
			cur += " " + w
		default:
			lines = append(lines, cur)
			cur = indent + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// standardExamples is c's Example with the S-6.7 lines: a --dry-run line
// after the first change example of a change command that shows none,
// and before each line with an approval flag, which ends with the
// approval comment.
func standardExamples(c *cobra.Command) string {
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
			// after the simplest call (S-6.6), its dry run
			out = append(out, l, dryRunLine(l))
			hasDry = true
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// exampleCommand is an example line without its comment.
func exampleCommand(l string) string {
	if i := strings.Index(l, "  #"); i > 0 {
		return strings.TrimRight(l[:i], " ")
	}
	return strings.TrimRight(l, " ")
}

// exampleOf: l is an example of c itself (not of another command, a
// pipe or a comment).
func exampleOf(c *cobra.Command, l string) bool {
	cmd := strings.TrimSpace(exampleCommand(l))
	if !strings.HasPrefix(cmd, "komando ") || strings.ContainsAny(cmd, "|<>$`;&") {
		return false
	}
	found, _, err := c.Root().Find(shellWords(cmd)[1:])
	return err == nil && found == c
}

// exampleFlags are the flags of an example line, up to `--` (S-6.7: the
// words after it belong to another program).
func exampleFlags(l string) []string {
	var flags []string
	for _, w := range shellWords(exampleCommand(l)) {
		if w == "--" {
			break
		}
		if strings.HasPrefix(w, "-") {
			flags = append(flags, strings.SplitN(w, "=", 2)[0])
		}
	}
	return flags
}

// dryRunLine is the example l as a dry run: without the approval flags,
// with --dry-run before `--` (or at the end), without its comment.
func dryRunLine(l string) string {
	cmd := exampleCommand(l)
	lead := cmd[:len(cmd)-len(strings.TrimLeft(cmd, " "))]
	words := strings.Fields(strings.TrimSpace(cmd))
	var keep []string
	dash := -1
	for _, w := range words {
		if w == "--" && dash < 0 {
			dash = len(keep)
		}
		if dash < 0 && (w == "--yes" || w == "-y" || w == "--allow-dangerous" || w == "--reveal") {
			continue
		}
		keep = append(keep, w)
	}
	if slices.Contains(keep, "--dry-run") {
		return lead + strings.Join(keep, " ")
	}
	if dash >= 0 {
		keep = append(keep[:dash], append([]string{"--dry-run"}, keep[dash:]...)...)
	} else {
		keep = append(keep, "--dry-run")
	}
	return lead + strings.Join(keep, " ")
}
