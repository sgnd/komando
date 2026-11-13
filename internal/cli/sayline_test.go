package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// A message komando writes on stderr for itself is one line in a pipe
// (an agent reading -o text, a script), and wrapped only at a terminal.
func TestSayLineOneLineInAPipe(t *testing.T) {
	savedFmt, savedW := out.P.Format, out.StderrWidth
	t.Cleanup(func() { out.P.Format, out.StderrWidth = savedFmt, savedW })
	out.P.Format = "text"
	rs := []execHostResult{{Host: "web1", RunResult: &sshx.RunResult{StdoutTruncated: true}}}

	out.StderrWidth = func() int { return 0 } // a pipe
	got := captureStderr(t, func() { truncationNotes(rs, 1<<20, true) })
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, "raise --max-output, or run it with `komando job start`") {
		t.Errorf("cut note in a pipe: %q", got)
	}

	out.StderrWidth = func() int { return 80 } // a terminal
	got = captureStderr(t, func() { truncationNotes(rs, 1<<20, true) })
	for _, l := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if len(l) > 80 && !strings.Contains(l, "`") {
			t.Errorf("cut note at a terminal: line of %d: %q", len(l), l)
		}
	}
	if strings.Count(got, "\n") < 2 || !strings.Contains(got, "\n  ") {
		t.Errorf("cut note at a terminal is not wrapped: %q", got)
	}
}
