package cli

import (
	"fmt"
	"os"
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
// policy blocks runs anyway, this once: a yes counts as --allow-dangerous
// for this check of this command only. Never under --dry-run, for an AI
// agent, a script or CI.
func policyAsk(rule string) bool {
	return confirmYes("Blocked by policy: " + rule + ". Run it anyway, this once?")
}

// confirmProtected asks a human at the terminal to confirm a change to
// protected targets. A yes counts as --yes for the rest of this command.
func confirmProtected(names []string) bool {
	askedAbout = names
	return confirmYes(fmt.Sprintf("%s %s protected. Change it anyway?", strings.Join(names, ", "), map[bool]string{true: "is", false: "are"}[len(names) == 1]))
}
