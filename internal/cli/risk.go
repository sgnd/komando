package cli

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/capability"
)

// One rule table says how much each command and flag combination needs
// before it runs (docs/design/command-standard.md, S-7.1 and S-7.2). It
// replaces two lists that disagreed: formDestructive, which decided when a
// person at a terminal types a name, and the safety stops in the commands
// themselves. Each row takes the higher tier of the two, so no stop is
// lost: a person now types the name for every command that stops an AI
// agent with POLICY_BLOCKED, and every command a person had to type a name
// for is in the table (TestStandardConfirmTable checks both against the
// stops TestAgentGolden records).
//
// The stops themselves stay in the commands (Guard, GuardConns,
// guardProtection, ...): they see what a table cannot, such as which
// server is protected or what a SQL statement does. A row marked dynamic
// gives the most the command can need; the command decides at run time.
// Like protection (T2), a cluster conn whose kubeconfig logs in with a
// command the policy blocks is decided by the target, for every cluster
// command, so it has no row.

// tier is how much a run needs, from nothing to a person at a terminal.
type tier int

const (
	tierRead      tier = iota // T0: looks only
	tierChange                // T1: reversible, or only komando's own list
	tierProtected             // T2: decided by the target (PROTECTED_TARGET)
	tierDangerous             // T3: cannot be undone, or an outage (POLICY_BLOCKED)
	tierSafety                // T3s: weakens komando's own checks (SAFETY_SETTING and friends)
	tierPerson                // T4: only a person at a terminal (NEEDS_PERSON and friends)
)

func (t tier) String() string {
	return [...]string{"read", "change", "protected", "dangerous", "safety", "person"}[t]
}

// riskRow is one row: the command (by its key), when it applies, its tier and
// what it does that cannot be undone (for the typed-name question).
type riskRow struct {
	key     safetyKey                 // the command's place (risk_keys.go)
	when    func(words []string) bool // nil: always
	cond    string                    // when, in words for `komando schema` (set with when)
	tier    tier
	what    string // "deletes the keys": the person reads "This deletes the keys."
	dynamic string // set: the tier holds only when this is so; the command decides
	bulk    string // set: a bulk confirm the command keeps (CONFIRM_REQUIRED)

	// typed: a T1 row (an agent needs nothing more, OD-7: easy to redo)
	// for which a person at the terminal who was asked for the command's
	// words also types the name of what goes; items says what those are
	typed, items string
}

// givesFlag: words give --name (or --name=true).
func givesFlag(name string) func([]string) bool {
	return func(w []string) bool { return slices.Contains(w, "--"+name) || slices.Contains(w, "--"+name+"=true") }
}

// switchesOn: the words only switch a rule on again: --off=false (in any
// spelling of false) or --rm-server or --rm-group, and no --off with another
// value and no --add-server or --add-group. cobra keeps a flag's last value,
// so anything else may run the off path. The v2.7 table
// (internal/capability/tier.go) says it with flags only and rates
// --off=false Safety too: stricter, never weaker (TestPolicyEditTableNotWeaker).
func switchesOn(w []string) bool {
	on := false
	for _, s := range w {
		name, val, _ := strings.Cut(s, "=")
		switch {
		case name == "--off" && slices.Contains([]string{"false", "0", "f", "F", "FALSE", "False"}, val):
			on = true
		case strings.HasPrefix(name, "--off") || strings.HasPrefix(name, "--add-"):
			return false
		case name == "--rm-server" || name == "--rm-group":
			on = true
		}
	}
	return on
}

// anyWord: one of words (an argument) is in set.
func anyWord(set ...string) func([]string) bool {
	return func(w []string) bool {
		return slices.ContainsFunc(w, func(s string) bool { return slices.Contains(set, s) })
	}
}

// sshUnit: a unit word is ssh or sshd (with .service or .socket).
func sshUnit(w []string) bool {
	return slices.ContainsFunc(w, func(s string) bool {
		s = strings.TrimSuffix(strings.TrimSuffix(s, ".service"), ".socket")
		return s == "ssh" || s == "sshd"
	})
}

// givesValue: words set --name to a value that is not empty.
func givesValue(name string) func([]string) bool {
	return func(w []string) bool {
		for i, s := range w {
			if v, ok := strings.CutPrefix(s, "--"+name+"="); ok && v != "" || s == "--"+name && i+1 < len(w) && w[i+1] != "" {
				return true
			}
		}
		return false
	}
}

// protectionOff: --protected=false (an edit that turns protection off).
func protectionOff(w []string) bool { return slices.Contains(w, "--protected=false") }

// riskRows is the table, keyed by (type, area, verb). Rows for one key are
// read in order; the highest tier that applies wins. It is built from
// internal/capability: the v2.7 rows that already stand for a command of
// today (TierRow.Today), and today's own rows (TodayRows) for the commands
// v2.7 replaces, removes or words differently. Both live there until the cut.
var riskRows = append(rowsOf(capability.TodayRows()), tableRows(capability.TierRows())...)

// tableRows turns the v2.7 rows marked Today into riskRows: the key without
// its provider is today's safety key.
func tableRows(rows []capability.TierRow) []riskRow {
	var out []riskRow
	for _, r := range rows {
		if !r.Today {
			continue
		}
		when, cond := condWhen(r.When)
		out = append(out, riskRow{key: safetyKey{r.Type, r.Area, r.Verb}, when: when, cond: cond,
			tier: tier(r.Tier), what: r.What, dynamic: r.Dynamic, bulk: r.Bulk})
	}
	return out
}

// condWhen is a v2.7 condition as a riskRow condition, and in words.
func condWhen(c capability.Cond) (func([]string) bool, string) {
	flags := make([]string, len(c.Flags))
	for i, f := range c.Flags {
		flags[i] = "--" + f
	}
	switch {
	case len(c.Words) > 0:
		return anyWord(c.Words...), strings.Join(c.Words, " ")
	case c.Not && len(c.Flags) == 1:
		return func(w []string) bool { return !givesFlag(c.Flags[0])(w) }, "without " + flags[0]
	case c.Value != "" && len(c.Flags) == 1:
		return anyWord(flags[0] + "=" + c.Value), "with " + flags[0] + "=" + c.Value
	case len(c.Flags) > 0:
		return func(w []string) bool {
			return !slices.ContainsFunc(c.Flags, func(f string) bool { return !givesFlag(f)(w) })
		}, "with " + strings.Join(flags, " ")
	}
	return nil, ""
}

// rowsOf turns capability's rows into riskRows. A condition name it does
// not know panics when the package starts, so every test fails at once.
func rowsOf(rows []capability.TodayRow) []riskRow {
	out := make([]riskRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, riskRow{key: safetyKey{r.Key.Type, r.Key.Area, r.Key.Verb}, when: namedWhen(r.When), cond: r.Cond,
			tier: tier(r.Tier), what: r.What, dynamic: r.Dynamic, bulk: r.Bulk, typed: r.Typed, items: r.Items})
	}
	return out
}

// namedWhen is the condition a row names: "flag:NAME", "value:NAME",
// "not-flag:NAME", "word:A,B", "all-flags:A,B", "any-flag:A,B", or one of
// one-arg, essential-package, ssh-unit, protection-off, rule-off.
func namedWhen(name string) func([]string) bool {
	if name == "" {
		return nil
	}
	kind, arg, _ := strings.Cut(name, ":")
	list := strings.Split(arg, ",")
	switch kind {
	case "flag":
		return givesFlag(arg)
	case "value":
		return givesValue(arg)
	case "not-flag":
		return func(w []string) bool { return !givesFlag(arg)(w) }
	case "word":
		return anyWord(list...)
	case "all-flags":
		return func(w []string) bool {
			return !slices.ContainsFunc(list, func(f string) bool { return !givesFlag(f)(w) })
		}
	case "any-flag":
		return func(w []string) bool {
			return slices.ContainsFunc(list, func(f string) bool { return givesFlag(f)(w) })
		}
	case "one-arg":
		return func(w []string) bool { return len(riskArgs(w)) == 1 }
	case "essential-package":
		return func(w []string) bool { return slices.ContainsFunc(riskArgs(w), essentialPkg) }
	case "ssh-unit":
		return sshUnit
	case "protection-off":
		return protectionOff
	case "rule-off":
		return func(w []string) bool { return !switchesOn(w) }
	}
	panic("risk row: unknown condition " + name)
}

// riskArgs are the words that are no flags (the positionals, roughly:
// a flag's value counts as a word, which only matters to group.rm, whose
// flags take none).
func riskArgs(w []string) []string {
	var a []string
	for _, s := range w {
		if s == "--" {
			break
		}
		if !strings.HasPrefix(s, "-") {
			a = append(a, s)
		}
	}
	return a
}

// riskOf is the row that decides command id with these words (its
// arguments and flags, without the command's own name), or a plain row
// from the command's kind: read (T0), change or depends (T1).
func riskOf(c *cobra.Command, words []string) riskRow {
	best := riskRow{tier: tierRead}
	if k, ok := kindOf(c); !ok || k.Kind != kindRead {
		best.tier = tierChange
	}
	for _, r := range rowsFor(c) {
		if r.when != nil && !r.when(words) {
			continue
		}
		if r.tier > best.tier || r.tier == best.tier && best.what == "" && best.dynamic == "" && best.bulk == "" {
			best = r
		}
	}
	return best
}

// rowsFor is the table's rows for c, in table order.
func rowsFor(c *cobra.Command) []riskRow {
	k, ok := cmdKeys[cmdID(c)]
	if !ok {
		return nil
	}
	var rows []riskRow
	for _, r := range riskRows {
		if r.key == k {
			rows = append(rows, r)
		}
	}
	return rows
}

// typedWhat is what the command does for good when a person must type a
// name before it runs (a T3 row that holds whatever the command runs, or a
// T1 row a person types the name for), or "".
func (r riskRow) typedWhat() string {
	switch {
	case r.tier == tierDangerous && r.dynamic == "":
		return r.what
	case r.typed != "":
		return r.typed
	}
	return ""
}

// commandTree gives the command tree lineWords reads, a new one each time.
// root.go sets it; a nil tree rates every line tierPerson (fail closed),
// so a caller that never set one cannot let a line through as a read.
var commandTree func() *cobra.Command

// riskOfLine is riskOf for a command line ("cache rm c1 k").
func riskOfLine(line []string) riskRow {
	if commandTree == nil {
		return riskRow{tier: tierPerson}
	}
	c, words, pos := lineWords(line)
	switch {
	case c == nil && rootOnly(line):
		return riskRow{tier: tierRead} // komando alone: first steps
	case c == nil, (!c.Runnable() || c.Annotations[groupOnly] == "true") && len(pos) > 0:
		// names no command: an unknown word, or words after a group that
		// name nothing under it (cut PR B2, as at the ssh gate)
		return riskRow{tier: tierPerson}
	}
	return riskOf(c, words)
}

// rootOnly reports whether line is komando alone, with global flags only.
func rootOnly(line []string) bool {
	root := commandTree()
	c, rest, err := root.Find(line)
	if err != nil || c != root || root.ParseFlags(rest) != nil {
		return false
	}
	return len(root.Flags().Args()) == 0
}

// lineWords finds the command of line and gives its words as riskOf
// reads them: the positional arguments, then each flag set as
// --name=value, then -- and what follows it. The command's own words
// (whatever name, alias or plural was typed) and a global flag before them
// are not among them. pos is the positional arguments before any --. c is
// nil when line names no command, or when there is no command tree.
func lineWords(line []string) (c *cobra.Command, words, pos []string) {
	if commandTree == nil {
		return nil, nil, nil
	}
	root := commandTree()
	c, rest, err := root.Find(line)
	if err != nil || c == root {
		return nil, nil, nil
	}
	if c.ParseFlags(rest) != nil {
		return c, rest, riskArgs(rest) // the run says what is wrong
	}
	args := c.Flags().Args()
	pos, after := args, []string(nil)
	if d := c.Flags().ArgsLenAtDash(); d >= 0 {
		pos, after = args[:d], args[d:]
	}
	words = slices.Clone(pos)
	c.Flags().Visit(func(f *pflag.Flag) {
		words = append(words, "--"+f.Name+"="+f.Value.String())
	})
	if after != nil {
		words = append(append(words, "--"), after...)
	}
	return c, words, pos
}

// riskRowIDs are the command IDs the rows name (TestTablesKeyedByID).
func riskRowIDs() []string {
	ids := make([]string, 0, len(riskRows))
	for _, r := range riskRows {
		ids = append(ids, keyID(r.key))
	}
	return ids
}

// flag is what an AI agent or a script adds for a tier: none for a read or
// a change, and none for a person-only step (no flag lifts it).
func (t tier) flag() string {
	switch t {
	case tierDangerous:
		return "--allow-dangerous"
	case tierProtected, tierSafety:
		return "--yes"
	}
	return ""
}

// confirmSchema is one approval of a command in `komando schema` (S-7.7):
// its tier, the flag an AI agent or a script adds for it, and when it
// holds ("" = always). A change on a protected server or conn also needs
// --yes (PROTECTED_TARGET); the target decides that, so it
// is no entry.
type confirmSchema struct {
	Tier string `json:"tier"`           // read, change, dangerous, safety or person
	Flag string `json:"flag,omitempty"` // --allow-dangerous or --yes
	When string `json:"when,omitempty"`
}

// confirmOf is c's approvals from the rule table: first the one it always
// has, then each one it reaches only sometimes, in table order.
func confirmOf(c *cobra.Command) []confirmSchema {
	always := confirmSchema{Tier: tierRead.String()}
	if k, ok := kindOf(c); !ok || k.Kind != kindRead {
		always.Tier = tierChange.String()
	}
	var more []confirmSchema
	for _, r := range rowsFor(c) {
		e := confirmSchema{Tier: r.tier.String(), Flag: r.tier.flag(), When: r.cond}
		switch {
		case r.bulk != "":
			e.Flag, e.When = "--yes", r.cond+": "+r.bulk+" (CONFIRM_REQUIRED)"
		case r.dynamic != "" && e.When != "":
			e.When += ", when " + r.dynamic
		case r.dynamic != "":
			e.When = "when " + r.dynamic
		}
		if e.When == "" {
			always = e
			continue
		}
		more = append(more, e)
	}
	res := []confirmSchema{always}
	for _, e := range more {
		if e.Tier != always.Tier || e.Flag != always.Flag {
			res = append(res, e) // one it always needs anyway says nothing more
		}
	}
	return res
}
