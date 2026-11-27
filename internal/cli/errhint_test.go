package cli

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestErrorHintCommands: every catalog hint names the command to run in
// backticks (S-8.5, C-E06), except the codes in hintWithoutCommand, and is
// never a question.
func TestErrorHintCommands(t *testing.T) {
	for _, c := range errorCodes {
		if strings.HasSuffix(strings.TrimSpace(c.Hint), "?") {
			t.Errorf("%s: a hint is a step, never a question: %q", c.Code, c.Hint)
		}
		has := strings.Contains(c.Hint, "`komando ")
		listed := slices.Contains(hintWithoutCommand, c.Code)
		switch {
		case !has && !listed:
			t.Errorf("%s: the hint names no `komando …` command (S-8.5): %q", c.Code, c.Hint)
		case has && listed:
			t.Errorf("%s: the hint names a command now; drop it from hintWithoutCommand", c.Code)
		}
	}
}

// hintCommandRe is a `komando …` command a hint names.
var hintCommandRe = regexp.MustCompile("`komando ([^`]*)`")

// TestHintCommandsExist: every `komando …` command a catalog hint names is
// one the tree has: its words up to the first flag or placeholder lead to a
// command, never to a group with a word it does not know (a moved or
// removed path).
func TestHintCommandsExist(t *testing.T) {
	root := newRoot(treeCall())
	for _, c := range errorCodes {
		for _, m := range hintCommandRe.FindAllStringSubmatch(c.Hint, -1) {
			var words []string
			for _, w := range strings.Fields(m[1]) {
				if strings.HasPrefix(w, "-") || strings.ContainsAny(w, "…<>|=/.@:'\"$*{}[]") || strings.ToUpper(w) == w {
					break
				}
				words = append(words, w)
			}
			if len(words) == 0 {
				continue
			}
			found, rest, err := root.Find(words)
			if err != nil || found == root || len(rest) > 0 && found.HasSubCommands() {
				t.Errorf("%s: the hint names `komando %s`, which is no command", c.Code, m[1])
			}
		}
	}
}
