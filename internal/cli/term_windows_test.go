package cli

import (
	"os"
	"testing"
)

// A pipe is no console: escape sequences are not turned on, and nothing
// is put back.
func TestConsoleVTPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ok, restore := consoleVT(int(w.Fd()))
	restore()
	if ok {
		t.Error("escape sequences turned on for a pipe")
	}
}
