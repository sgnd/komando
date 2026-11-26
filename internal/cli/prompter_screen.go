package cli

import "strings"

// The interactive mode (C162) is a keyboard screen for a person at a
// terminal: it only builds a command line, which then runs like a typed
// one (design note 2026-11-25). This file is its start rule, before any
// screen code exists. Nothing calls it yet.

// interactiveOn is the switch of the interactive mode. It stays false
// until the v0.18.0 cut turns it on in code: no environment variable or
// flag can turn it on.
const interactiveOn = false

// screenGate is the start rule of the interactive mode, conditions 1 to 8
// of the design note: the switch is on, stdin, stderr (terminal) and
// stdout are terminals, promptGate lets komando ask (no AI agent, not CI,
// not TERM=dumb, text output), and the line carries no approval flag.
// Whatever fails, nobody sees the screen.
func screenGate(on, terminal, stdoutTerminal, agent bool, ci, termName, format string, args []string) bool {
	return on && terminal && stdoutTerminal && promptGate(format, agent, ci, termName) && !carriesApproval(args)
}

// carriesApproval says whether args hold --yes, --allow-dangerous or
// --reveal (with or without a value; approvalFlag in flag_help.go), or a
// short -y in a group (-ny): a line that carries one is a decision made,
// and no screen completes it (S-7.1, S-7.6). It errs on the side of no
// screen: a value that only looks like one (after --, or in -oyaml) also
// counts.
func carriesApproval(args []string) bool {
	for _, a := range args {
		if approvalFlag.MatchString(a) || len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a[1:], 'y') {
			return true
		}
	}
	return false
}
