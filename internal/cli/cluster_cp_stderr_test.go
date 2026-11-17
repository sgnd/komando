package cli

import (
	"bytes"
	"testing"
)

// What a pod writes on stderr is kept up to podErrMax; the rest is read
// and dropped, so the copy still ends normally.
func TestPodErrIsCapped(t *testing.T) {
	var b bytes.Buffer
	w := &limitWriter{w: &b, n: podErrMax}
	chunk := bytes.Repeat([]byte("e"), 1<<20)
	for range 8 {
		if n, err := w.Write(chunk); err != nil || n != len(chunk) {
			t.Fatalf("write: %d %v", n, err)
		}
	}
	if b.Len() != podErrMax {
		t.Errorf("kept %d bytes, want %d", b.Len(), podErrMax)
	}
}
