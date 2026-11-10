//go:build !windows

package cli

import (
	"io"
	"os"
	"testing"
	"time"
)

// The login goes through a pipe once, and a pipe nobody reads does not
// keep komando waiting.
func TestAuthPipe(t *testing.T) {
	dir := t.TempDir()
	p, done, err := authPipe(dir, "office", "user\npass\n")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode()&os.ModeNamedPipe == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("not a private pipe: %v %v", fi.Mode(), err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "user\npass\n" {
		t.Fatalf("read %q", b)
	}
	done()
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("pipe or its folder left: %v", ents)
	}

	_, done2, err := authPipe(dir, "never-read", "x\ny\n")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	done2()
	if time.Since(start) > 3*time.Second {
		t.Fatal("done waited for a reader that never came")
	}
}
