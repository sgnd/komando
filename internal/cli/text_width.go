package cli

import "github.com/sgnd/komando/internal/out"

// An AI agent reads each error, hint and warning on one line, even at a
// terminal: the wrap at 80 columns (M-9) is for a person's eyes.
func init() {
	termWidth := out.StderrWidth
	out.StderrWidth = func() int {
		if isAgent() {
			return 0
		}
		return termWidth()
	}
}
