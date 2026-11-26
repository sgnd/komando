package interactive

import "github.com/sgnd/komando/internal/cli/kit/term"

// Review is the last screen: the line built from the answers, as
// internal/cli prints it (quoted, secrets masked), before it runs.
type Review struct {
	line string
}

// NewReview shows line, the words after komando.
func NewReview(line string) *Review { return &Review{line: line} }

// Key applies one key: Enter runs the line, Esc goes back to the form,
// Ctrl-C quits.
func (r *Review) Key(k term.Key) Result {
	switch k.Kind {
	case term.KeyEnter:
		return Take
	case term.KeyEsc:
		return Back
	case term.KeyInterrupt:
		return Quit
	}
	return Stay
}
