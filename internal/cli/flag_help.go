package cli

import (
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Help for a mistyped flag: the closest long flag, a did-you-mean for an
// unknown short letter, and the example that shows a flag in use.

// closestFlag is the flag of cmd (its own or inherited) nearest to a
// mistyped name, or "" when none is near enough to be a typo.
func closestFlag(cmd *cobra.Command, typed string) string {
	best, bestD := "", 3 // more than 2 typos is not a typo
	var prefixed []string
	visit := func(f *pflag.Flag) {
		if f.Hidden || f.Deprecated != "" {
			return
		}
		if d := editDistance(typed, f.Name); d < bestD {
			best, bestD = f.Name, d
		}
		if len(typed) >= 3 && strings.HasPrefix(f.Name, typed) {
			prefixed = append(prefixed, f.Name)
		}
	}
	cmd.Flags().VisitAll(visit)
	cmd.InheritedFlags().VisitAll(visit)
	if best == "" && len(prefixed) == 1 {
		best = prefixed[0] // --conn for --connect-timeout
	}
	return best
}

// shorthandSuggest is the did-you-mean for an unknown short letter typed in
// word (S-5.16): first the habits of other tools (-it, -n, -L, -w), then
// the long flags of cmd that start with the same letter, at most two.
func shorthandSuggest(cmd *cobra.Command, letter, word string) string {
	has := func(name string) bool { f := cmd.Flags().Lookup(name); return f != nil && !f.Hidden }
	switch {
	case word == "-it" || word == "-ti":
		if strings.HasPrefix(cmd.CommandPath(), "komando cluster") {
			return "komando runs one command and returns; for a shell in a pod: `komando cluster shell TARGET POD`"
		}
		return "komando runs one command and returns; for a shell on a server: `komando shell TARGET`"
	case letter == "n" && has("limit"):
		return "did you mean --limit?"
	case letter == "L" || letter == "R" || letter == "D":
		return "port forwarding is `komando tunnel start TARGET -" + letter + " SPEC`"
	case letter == "w" && has("wait"):
		return "did you mean --wait?"
	}
	var near []string
	visit := func(f *pflag.Flag) {
		// never an approval flag: a typo is no reason to hand one out
		if !f.Hidden && f.Deprecated == "" && strings.HasPrefix(f.Name, strings.ToLower(letter)) && !approvalFlag.MatchString("--"+f.Name) && !slices.Contains(near, "--"+f.Name) {
			near = append(near, "--"+f.Name)
		}
	}
	cmd.Flags().VisitAll(visit)
	if len(near) == 0 || len(near) > 2 {
		return ""
	}
	return "did you mean " + strings.Join(near, " or ") + "?"
}

// exampleWith is the first example of cmd that uses flag, or "".
func exampleWith(cmd *cobra.Command, flag string) string {
	for _, l := range strings.Split(cmd.Example, "\n") {
		l = strings.TrimSpace(l)
		if i := strings.Index(l, "  #"); i > 0 {
			l = strings.TrimSpace(l[:i])
		}
		if slices.Contains(strings.Fields(l), flag) && !approvalFlag.MatchString(l) {
			return l
		}
	}
	return ""
}

func firstExample(cmd *cobra.Command) string {
	for _, l := range strings.Split(cmd.Example, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			if i := strings.Index(l, "  #"); i > 0 {
				l = strings.TrimSpace(l[:i])
			}
			// a typo is no reason to hand an AI agent a flag that skips a
			// safety stop: the first example without one
			if approvalFlag.MatchString(l) {
				continue
			}
			return l
		}
	}
	return ""
}

// approvalFlag: --yes, -y, --allow-dangerous or --reveal on a command line.
var approvalFlag = regexp.MustCompile(`(^|\s)(--yes|-y|--allow-dangerous|--reveal)(\s|=|$)`)
