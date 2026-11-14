package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// A secret piped on stdin is read up to 1 MiB: a wrong pipe stops with a
// clear USAGE error instead of filling memory, and nothing is stored.
func TestSecretSetStdinOverLimit(t *testing.T) {
	invHome(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := tcl.stdin
	tcl.stdin = r
	t.Cleanup(func() { tcl.stdin = saved; r.Close() })
	go func() {
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for i := 0; i < 32; i++ { // 2 MiB, or until komando stops reading
			if _, err := w.Write(chunk); err != nil {
				break
			}
		}
		w.Close()
	}()
	e := wantCode(t, "USAGE", "secret", "set", "big")
	if !strings.Contains(e.Message, "the value on stdin is more than 1.0 MiB") {
		t.Errorf("message: %+v", e)
	}
}

func TestReadLimited(t *testing.T) {
	if b, err := readLimited(strings.NewReader("abcd"), 4, "x"); err != nil || string(b) != "abcd" {
		t.Errorf("at the limit: %q %v", b, err)
	}
	if _, err := readLimited(strings.NewReader("abcde"), 4, "the value"); err == nil || !strings.Contains(err.Error(), "the value on stdin is more than 4 B") {
		t.Errorf("over the limit: %v", err)
	}
	if b, err := readLimited(strings.NewReader("abcde"), 0, "x"); err != nil || len(b) != 5 {
		t.Errorf("no limit: %q %v", b, err)
	}
}
