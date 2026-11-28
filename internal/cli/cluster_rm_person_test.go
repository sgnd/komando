package cli

import (
	"io"
	"os"
	"testing"
)

// personAnswers makes this test a person at a terminal who types lines.
func personAnswers(t *testing.T, lines string) {
	t.Helper()
	saved, savedIn := tcl.terminal, tcl.stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() { io.WriteString(w, lines); w.Close() }()
	tcl.stdin = r
	tcl.terminal = true
	t.Cleanup(func() { tcl.terminal, tcl.stdin = saved, savedIn; r.Close(); resetApproval() })
}
