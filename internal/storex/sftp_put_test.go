//go:build !windows

package storex

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"

	"github.com/sgnd/komando/internal/out"
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

// noModeSFTP is OpenSSH's sftp-server with setting modes forbidden (storage
// boxes, SFTP-only accounts); it makes files and folders with umask.
func noModeSFTP(t *testing.T, umask string) *sftp.Client {
	t.Helper()
	var bin string
	for _, b := range []string{"/usr/libexec/sftp-server", "/usr/lib/openssh/sftp-server", "/usr/lib/ssh/sftp-server"} {
		if _, err := os.Stat(b); err == nil {
			bin = b
		}
	}
	if bin == "" {
		t.Skip("no OpenSSH sftp-server here")
	}
	cmd := exec.Command(bin, "-u", umask, "-e", "-l", "QUIET", "-P", "setstat,fsetstat,lsetstat")
	w, _ := cmd.StdinPipe()
	r, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc, err := sftp.NewClientPipe(r, w)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sc.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return sc
}

// A server that will not make the upload's folder private gets
// CHMOD_FAILED, and nothing is written: other users of the server could
// read the file while it goes in. One that makes it private anyway works.
func TestSFTPPutRefusesAnOpenFolder(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	b := NewSFTP(noModeSFTP(t, "022"), strings.TrimPrefix(dir, "/")+"/", nil)
	err := b.Put(context.Background(), "data.txt", strings.NewReader("secret\n"), 7, "")
	if e, ok := err.(*out.Error); !ok || e.Code != "CHMOD_FAILED" {
		t.Fatalf("got %v, want CHMOD_FAILED", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	b = NewSFTP(noModeSFTP(t, "077"), strings.TrimPrefix(dir, "/")+"/", nil)
	if err := b.Put(context.Background(), "data.txt", strings.NewReader("secret\n"), 7, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "data.txt")); string(got) != "secret\n" {
		t.Fatalf("upload: %q", got)
	}
}
