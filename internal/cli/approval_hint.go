package cli

import (
	"slices"
	"strings"

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
func stdApprovalHint(cl *call, e *out.Error) bool {
	if e == nil || e.Exit != out.ExitPolicy || e.Final {
		return false
	}
	flags := e.Flags()
	if len(flags) == 0 || slices.Contains(flags, "--reveal") {
		return false
	}
	e.Hint = approvalText(cl, flags, cl.isAgent(), cl.flags.dryRun)
	return true
}

// approvalText is the hint for flags: for an AI agent or not, in a dry
// run or not.
func approvalText(cl *call, flags []string, agent, dry bool) string {
	f := joinAnd(flags)
	const window = " (komando then asks them in a window on their screen)"
	args := cl.args[1:]
	switch {
	case agent && dry:
		return "ask the user; once they agree, run it again without --dry-run and with " + f + window
	case agent:
		return "check with --dry-run, ask the user; once they agree, run it again with " + f + window
	case dry && plainLine(args):
		return "run it again without --dry-run and with " + f + ": `" + lineWith(args, flags, true) + "`"
	case dry:
		return "run it again without --dry-run and with " + f + beforeDash(args)
	case plainLine(args):
		return "check with --dry-run, then run it again with " + f + ": `" + lineWith(args, flags, false) + "`"
	}
	return "check with --dry-run, then run it again with " + f + beforeDash(args)
}

// beforeDash says where the flags go when args hold a --.
func beforeDash(args []string) string {
	if slices.Contains(args, "--") {
		return " (before the --)"
	}
	return ""
}

// secretFlag reports whether the value of the flag name may be a secret:
// the hint never repeats a line with one of them.
func secretFlag(name string) bool {
	return strings.Contains(name, "pass") || strings.Contains(name, "token") || strings.Contains(name, "secret") ||
		slices.Contains([]string{"content", "value", "env", "old", "new", "header", "data", "body"}, name)
}

// plainLine reports whether the hint may repeat args: no words for another
// program (after --), no free text (a word with a space or a quote), no
// value the mask would hide and no flag whose value may be a secret. A
// line with any of them could put a password into error.hint, which lands
// in CI logs.
func plainLine(args []string) bool {
	for _, a := range args {
		if a == "--" || strings.ContainsAny(a, " \t\n'\"`") || out.MaskSecrets(a) != a {
			return false
		}
		if name, ok := strings.CutPrefix(a, "--"); ok {
			name, _, _ = strings.Cut(name, "=")
			if secretFlag(name) {
				return false
			}
		}
	}
	return out.MaskSecrets(strings.Join(args, " ")) == strings.Join(args, " ")
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

// approvalErr is a stop a flag lifts (C-C10): POLICY_BLOCKED
// (--allow-dangerous), or PROTECTED_HOST, PROTECTED_TARGET, SAFETY_SETTING,
// SECRET_DESTINATION, OPEN_BIND and CONFIRM_REQUIRED (--yes). why says what
// would happen; need adds the other flags the real run needs (--yes on a
// protected target). The hint is the one approval hint for every one of
// those flags, for an agent or a script, as approvalHint gives at exit.
func approvalErr(cl *call, code, why string, need ...string) *out.Error {
	e := out.Errf(out.ExitPolicy, code, "", "%s", why).Need(need...)
	e.Hint = approvalText(cl, e.Flags(), cl.isAgent(), cl.flags.dryRun)
	return e
}
