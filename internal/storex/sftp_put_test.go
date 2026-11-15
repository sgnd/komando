//go:build !windows

package storex

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

func localSFTP(t *testing.T) *sftp.Client {
	t.Helper()
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	srv, err := sftp.NewServer(struct {
		io.Reader
		io.WriteCloser
	}{sr, sw})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	sc, err := sftp.NewClientPipe(cr, cw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cw.Close(); sw.Close(); sc.Close(); srv.Close() })
	return sc
}

// A link another server user planted under the upload's temporary name
// is never written through: the upload goes to a temporary file of its
// own, made exclusively, and no file is left behind.
func TestSFTPPutIgnoresPlantedLink(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, ".komando-upload-data.txt")); err != nil {
		t.Fatal(err)
	}
	b := NewSFTP(localSFTP(t), strings.TrimPrefix(dir, "/")+"/", nil)
	if err := b.Put(context.Background(), "data.txt", strings.NewReader("new\n"), 4, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep\n" {
		t.Fatalf("written through the planted link: %q", got)
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o644 {
		t.Fatalf("victim mode changed: %v", fi.Mode())
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "data.txt")); string(got) != "new\n" {
		t.Fatalf("upload: %q", got)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".komando-*"))
	if len(left) != 1 { // only the planted link
		t.Fatalf("left behind: %v", left)
	}
}
