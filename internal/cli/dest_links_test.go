//go:build !windows

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A symbolic link inside the folder a download or sync writes into is
// never followed: the file would land wherever it leads. --delete never
// removes a file through one either.
func TestDestinationLinksAreNotFollowed(t *testing.T) {
	sc := localSFTP(t)
	src := filepath.Join(t.TempDir(), "site")
	os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	os.WriteFile(filepath.Join(src, "sub", "x.conf"), []byte("server"), 0o644)
	outside := t.TempDir()
	dst := filepath.Join(t.TempDir(), "site")
	os.MkdirAll(dst, 0o755)
	if err := os.Symlink(outside, filepath.Join(dst, "sub")); err != nil {
		t.Fatal(err)
	}
	_, err := download(context.Background(), nil, sc, src+"/", dst, cpOpts{recursive: true, overwrite: true})
	if e := toErr(err); e == nil || e.Code != "UNSAFE_PATH" || !strings.Contains(e.Message, "symbolic link") {
		t.Fatalf("download: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "x.conf")); err == nil {
		t.Fatal("download wrote through the link")
	}
	l := localSide{root: dst}
	if err := l.write(context.Background(), "sub/x.conf", strings.NewReader("s"), syncFile{}); toErr(err).Code != "UNSAFE_PATH" {
		t.Errorf("sync write: %v", err)
	}
	os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("mine"), 0o644)
	if err := l.remove(context.Background(), "sub/keep.txt"); toErr(err).Code != "UNSAFE_PATH" {
		t.Errorf("sync --delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep.txt")); err != nil {
		t.Error("--delete removed a file outside the folder")
	}
	// a file that is itself a link is replaced, not written through
	os.WriteFile(filepath.Join(outside, "target.txt"), []byte("theirs"), 0o644)
	os.Symlink(filepath.Join(outside, "target.txt"), filepath.Join(dst, "top.txt"))
	if err := l.write(context.Background(), "top.txt", strings.NewReader("new"), syncFile{}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "target.txt")); string(b) != "theirs" {
		t.Errorf("the link's target was changed: %q", b)
	}
}
