package cli

import (
	"os"
	"slices"

	"github.com/sgnd/komando/internal/out"
)

// One helper words every approval hint (S-8.6, C-C10): a stop that a flag
// lifts (--allow-dangerous, --yes) gets one fixed sentence that names every
// flag the real run needs, in two variants. An AI agent is told to ask the
// user first; a script or a person gets the whole command line to run.
// The hints the stops are built with stay as a fallback for the few paths
// that do not end here (a result per server).

// stdApprovalHint sets e's hint to the approval hint when a flag lifts e,
// and says whether it did. --reveal keeps its own hint: it never counts in
// a dry run.
func stdApprovalHint(e *out.Error) bool {
	if e == nil || e.Exit != out.ExitPolicy || e.Final {
		return false
	}
	flags := e.Flags()
	if len(flags) == 0 || slices.Contains(flags, "--reveal") {
		return false
	}
	e.Hint = approvalText(flags, isAgent(), g.dryRun)
	return true
}

// approvalText is the hint for flags: for an AI agent or not, in a dry
// run or not.
func approvalText(flags []string, agent, dry bool) string {
	f := joinAnd(flags)
	const window = " (komando then asks them in a window on their screen)"
	switch {
	case agent && dry:
		return "ask the user; once they agree, run it again without --dry-run and with " + f + window
	case agent:
		return "check with --dry-run, ask the user; once they agree, run it again with " + f + window
	case dry:
		return "run it again without --dry-run and with " + f + ": `" + lineWith(os.Args[1:], flags, true) + "`"
	}
	return "check with --dry-run, then run it again with " + f + ": `" + lineWith(os.Args[1:], flags, false) + "`"
}

// lineWith is the command line args with flags added before a `--` (when
// not there already), and without --dry-run when dropDry.
func lineWith(args, flags []string, dropDry bool) string {
	end := slices.Index(args, "--")
	if end < 0 {
		end = len(args)
	}
	var w []string
	for _, a := range args[:end] {
		if dropDry && (a == "--dry-run" || a == "--dry-run=true") {
			continue
		}
		w = append(w, a)
	}
	for _, f := range flags {
		if !slices.Contains(args[:end], f) {
			w = append(w, f)
		}
	}
	return commandLineOf(append(w, args[end:]...))
}

// protNeed: on protected targets the real run needs --yes too.
func protNeed(prot []string) []string {
	if len(prot) > 0 {
		return []string{"--yes"}
	}
	return nil
}
