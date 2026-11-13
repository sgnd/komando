package cli

import (
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// Suggestions for a word komando does not know (S-5.17, S-8.8): the word
// komando thinks was meant goes in the additive error.suggestion, and the
// hint is the whole command line with that word in place, so an agent
// that reads only the hint can run it. A person reads the "did you mean"
// in the message.

// habitWords are words people type from another tool's habit, by the
// command that does that job (its path under komando): typing one
// suggests that command.
var habitWords = map[string][]string{
	"facts": {"inspect"}, // docker inspect
	"svc":   {"systemd"},
}

// suggestHabitWords lets each command in habitWords suggest itself for its
// words (unknownCommandErr then names only that command).
func suggestHabitWords(root *cobra.Command) {
	for path, words := range habitWords {
		if c, _, err := root.Find(strings.Fields(path)); err == nil && c != root {
			c.SuggestFor = append(c.SuggestFor, words...)
		}
	}
}

// suggest records right as the suggestion for wrong: error.suggestion, and
// a hint with the command line it gives.
func suggest(e *out.Error, wrong, right string) *out.Error {
	e.Suggestion = right
	if line, ok := swappedLine(os.Args[1:], wrong, right); ok {
		e.Hint = "run it again with " + right + ": `" + line + "`"
	} else if e.Hint != "" {
		e.Hint = "use " + right + "; " + e.Hint
	} else {
		e.Hint = "use " + right
	}
	return e
}

// swappedLine is the command line args with the word wrong replaced by
// right, also as one part of a list (--via a,wrong) or of --flag=wrong.
func swappedLine(args []string, wrong, right string) (string, bool) {
	if wrong == "" {
		return "", false
	}
	found := false
	w := slices.Clone(args)
	for i, a := range w {
		if found {
			break
		}
		if a == wrong {
			w[i], found = right, true
			continue
		}
		if a == "--" { // a remote command's words are its own
			break
		}
		parts := strings.FieldsFunc(a, func(r rune) bool { return r == ',' || r == '=' })
		if slices.Contains(parts, wrong) {
			var b strings.Builder
			tok := ""
			flush := func() {
				if tok == wrong && !found {
					tok, found = right, true
				}
				b.WriteString(tok)
				tok = ""
			}
			for _, r := range a {
				if r == ',' || r == '=' {
					flush()
					b.WriteRune(r)
					continue
				}
				tok += string(r)
			}
			flush()
			w[i] = b.String()
		}
	}
	if !found {
		return "", false
	}
	return commandLineOf(w), true
}

// nearWords are the names within reach of word (S-5.17): an edit distance
// of 1 for a word of 4 letters or fewer, 2 for a longer one; the closest
// first, at most two.
func nearWords(word string, names []string) []string {
	limit := 2
	if len([]rune(word)) <= 4 {
		limit = 1
	}
	type cand struct {
		name string
		d    int
	}
	var cs []cand
	for _, n := range names {
		if d := editDistance(strings.ToLower(word), strings.ToLower(n)); d <= limit && !slices.ContainsFunc(cs, func(c cand) bool { return c.name == n }) {
			cs = append(cs, cand{n, d})
		}
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].d < cs[j].d || cs[i].d == cs[j].d && cs[i].name < cs[j].name })
	var res []string
	for _, c := range cs {
		if len(res) == 2 {
			break
		}
		res = append(res, c.name)
	}
	return res
}

// commandNames are the names a person may type for cmd's sub-commands:
// each visible one's name.
func commandNames(cmd *cobra.Command) []string {
	var names []string
	for _, c := range cmd.Commands() {
		if c.IsAvailableCommand() {
			names = append(names, c.Name())
		}
	}
	return names
}

// foreignWords are words from other tools people type at komando's top
// level, and the komando command that does that job (S-5.17).
var foreignWords = map[string]string{
	"get":        "list",
	"ps":         "docker ps TARGET",
	"kubectl":    "cluster run TARGET -- ...",
	"helm":       "cluster helm list TARGET",
	"psql":       "db query CONN",
	"mysql":      "db query CONN",
	"redis-cli":  "cache run CONN -- ...",
	"apt":        "pkg",
	"apt-get":    "pkg",
	"yum":        "pkg",
	"dnf":        "pkg",
	"systemctl":  "svc",
	"journalctl": "logs TARGET",
	"ssh":        "shell SERVER",
	"scp":        "cp",
	"rsync":      "sync",
	"crontab":    "cron list TARGET",
	"aws":        "login aws",
	"ls":         "list",
	"rm":         "host rm NAME",
	"delete":     "host rm NAME",
	"remove":     "host rm NAME",
	"del":        "host rm NAME",
}

// foreignCommand is the komando command for a foreign word at the top
// level, given the words after it. A delete word followed by a komando
// noun means that noun's rm (`komando delete conn x` is `conn rm x`).
func foreignCommand(root *cobra.Command, word string, rest []string) (string, bool) {
	cmd, ok := foreignWords[strings.ToLower(word)]
	if !ok {
		return "", false
	}
	if strings.HasSuffix(cmd, " rm NAME") && len(rest) > 0 {
		if c, _, err := root.Find(rest[:1]); err == nil && c != root && c.HasSubCommands() {
			if rm, _, err := c.Find([]string{"rm"}); err == nil && rm != c {
				return strings.TrimSpace(c.Name() + " rm " + strings.Join(rest[1:], " ")), true
			}
		}
		if len(rest) == 1 {
			return "host rm " + rest[0], true
		}
	}
	return cmd, true
}

// unknownCommandErr is the usage error for a word that names no command
// of cmd (S-5.17): a foreign word's komando command first, then the
// nearest names; the hint names a command only when there is exactly one.
func unknownCommandErr(cmd *cobra.Command, word string, rest []string) *out.Error {
	e := out.Usage("unknown command %q", word)
	if cmd.HasParent() {
		e = out.Usage("unknown command %q for %q", word, cmd.CommandPath())
	} else if fc, ok := foreignCommand(cmd, word, rest); ok {
		e.Message += "; komando does this with `komando " + fc + "`"
		e.Suggestion = fc
		e.Hint = "run `komando " + fc + "` instead"
		return e
	}
	near := nearWords(word, commandNames(cmd))
	for _, c := range cmd.Commands() {
		if slices.Contains(c.SuggestFor, word) { // a habit word: only the command that does that job
			near = []string{c.Name()}
		}
	}
	switch len(near) {
	case 0:
		e.Hint = "see `" + cmd.CommandPath() + " --help` for the list of commands"
	case 1:
		e.Message += "; did you mean " + near[0] + "?"
		suggest(e, word, near[0])
	default:
		e.Message += "; did you mean " + strings.Join(near, " or ") + "?"
		e.Hint = "see `" + cmd.CommandPath() + " --help` for the list of commands"
	}
	return e
}
