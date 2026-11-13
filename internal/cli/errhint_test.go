package cli

import (
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
