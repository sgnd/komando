package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// Passthrough commands hand words to another program: exec, job start,
// docker exec/compose/raw, cluster exec/shell/run and cache run (every
// command whose Use has `-- COMMAND...` or `-- ARGS...`). komando reads its
// own flags anywhere before `--`, so every word for the other program must
// come after `--`: without it, `komando exec web1 apt-get install -y nginx`
// would read -y as --yes (an approval no one gave), and a trailing
// --dry-run would be taken by komando while the rest ran on the server.
// Such a word is a usage error, always (docs/design/command-standard.md,
// S-4.4). applyConventions adds the check to every passthrough command.
//
// The check runs with the argument rule, before the root's checks: a
// command that will be refused must not first ask a person to allow the
// -y it would have misread.

// passthroughFixed is how many positionals come before `--` in a
// passthrough command's Use line, or -1 for a command that is not one.
func passthroughFixed(use string) int {
	f := strings.Fields(use)
	for i, w := range f {
		if (w == "--" || w == "[--]" || w == "[--") && i+1 < len(f) && strings.HasSuffix(strings.Trim(f[len(f)-1], "[]"), "...") {
			return i - 1 // without the command's own name
		}
	}
	return -1
}

// needDash adds the `--` check to c's argument rule, after the rule
// itself (so a missing argument is reported as before). It checks only
// arguments komando parsed: a rule called on its own (to learn how many
// arguments a command takes) sees no -- and is not refused.
func needDash(c *cobra.Command, fixed int) {
	prev := c.Args
	c.Args = func(cmd *cobra.Command, args []string) error {
		if prev != nil {
			if err := prev(cmd, args); err != nil {
				return err
			}
		}
		if !cmd.Flags().Parsed() {
			return nil
		}
		return dashCheck(cmd, args, fixed)
	}
}

// dashCheck refuses words after the first fixed positionals that do not
// come after `--`.
func dashCheck(cmd *cobra.Command, args []string, fixed int) error {
	end := len(args)
	if d := cmd.ArgsLenAtDash(); d >= 0 {
		end = d
	}
	if end <= fixed {
		return nil
	}
	return out.Errf(out.ExitUsage, "USAGE",
		"put -- before the command: `"+dashExample(cmd)+"`; komando reads its own flags (-y, --dry-run, -P) only before --",
		"komando %s takes the words for %s after --; nothing was run", strings.TrimPrefix(cmd.CommandPath(), "komando "), dashWho(cmd))
}

// dashExample is the command's first example with `--`.
func dashExample(cmd *cobra.Command) string {
	for _, l := range strings.Split(cmd.Example, "\n") {
		l, _, _ = strings.Cut(strings.TrimSpace(l), "   #")
		if strings.HasPrefix(l, "komando ") && strings.Contains(l, " -- ") {
			return strings.TrimSpace(l)
		}
	}
	return "komando exec web1 -- apt-get install -y nginx"
}

// dashWho is what gets the words after --.
func dashWho(cmd *cobra.Command) string {
	switch strings.Fields(strings.TrimPrefix(cmd.CommandPath(), "komando "))[0] {
	case "docker":
		return "docker"
	case "cluster":
		return "the cluster"
	case "cache":
		return "the cache"
	}
	return "the server"
}
