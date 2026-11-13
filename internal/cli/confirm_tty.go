package cli

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// What a person answers at the terminal: never in CI, and every yes noted
// for the audit (confirm: tty).

// ciRun: CI is set (and not false or 0). A CI job is never a person, even
// on a terminal, so nothing is asked there and no answer counts as a yes.
func ciRun() bool {
	ci := os.Getenv("CI")
	return ci != "" && ci != "false" && ci != "0"
}

// ttyYes notes a yes a person typed at the terminal for this command: the
// audit records it as confirm: tty, with what was asked.
func ttyYes(what string) {
	c := cur()
	c.ttyYes = append(c.ttyYes, what)
}

// policyAsk asks a person at the terminal whether a command the safety
// policy blocks runs anyway, this once, by typing the name of the conn or
// server it is about (names): a hit is a T3, so a [y/N] is not enough (S-7.2). A right
// answer counts as --allow-dangerous for this check of this command only.
// Never under --dry-run, for an AI agent, a script or CI.
func policyAsk(rule string, names ...string) bool {
	if g.dryRun || !interactive() {
		return false
	}
	fmt.Fprintf(os.Stderr, "Blocked by policy: %s.\n", rule)
	want, shown := typedAnswer(names, "the number of targets")
	ok := want != "" && ask("Type "+shown+" to run it anyway, this once: ") == want
	cur().sess.SaidNo(!ok)
	if ok {
		ttyYes("typed " + want + ": blocked by policy: " + rule)
	}
	return ok
}

// confirmProtected asks a person at the terminal to confirm a change to
// protected targets. A yes counts as --yes for the rest of this command.
// Targets a typed answer covered already (confirmDangerousOn) are not
// asked about again.
func confirmProtected(names []string) bool {
	if len(names) > 0 && !slices.ContainsFunc(names, func(n string) bool { return !slices.Contains(cur().typedProt, n) }) {
		return true
	}
	askedAbout = names
	it := map[bool]string{true: "it", false: "them"}[len(names) == 1]
	return confirmYes(fmt.Sprintf("%s (protected): this command changes %s. Continue?", strings.Join(names, ", "), it))
}
