//go:build !windows

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// peekReader looks at the staged temporary file while its content goes in.
type peekReader struct {
	dir   string
	parts []string
	seen  []string // what another user could do with each .komando-* entry
}

func (r *peekReader) Read(b []byte) (int, error) {
	ms, _ := filepath.Glob(filepath.Join(r.dir, ".komando-*"))
	for _, m := range ms {
		if fi, err := os.Lstat(m); err == nil {
			r.seen = append(r.seen, openToOthers(fi))
		}
	}
	if len(r.parts) == 0 {
		return 0, io.EOF
	}
	n := copy(b, r.parts[0])
	r.parts = r.parts[1:]
	return n, nil
}

// openToOthers is "" for an entry no other user can open or enter (a
// folder 0700, a file 0600), else what it is.
func openToOthers(fi os.FileInfo) string {
	if fi.Mode().Perm()&0o077 == 0 {
		return ""
	}
	return fmt.Sprintf("%s %04o", fi.Name(), fi.Mode().Perm())
}

// checkStaged fails unless the staged file was seen, and only ever where
// no other user could open it, not even for a moment after it was made
// (pkg/sftp creates it at the server's default mode, often 0644).
func checkStaged(t *testing.T, r *peekReader) {
	t.Helper()
	if len(r.seen) == 0 {
		t.Fatal("the staged file was not seen")
	}
	for _, s := range r.seen {
		if s != "" {
			t.Fatalf("another user could open the staged file while the content went in: %s", s)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(r.dir, ".komando-*")); left != nil {
		t.Fatalf("staged file left: %v", left)
	}
}

// The staged file holds secrets ({{secret:NAME}} already filled in): only
// the SSH user may read it while it is written, whatever the final mode.
func TestWriteStagesPrivately(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0o022))
	sc := localSFTP(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(p, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &peekReader{dir: dir, parts: []string{"DB_PASSWORD=", "s3cret\n"}}
	res, err := writeRemoteFrom(tcl, context.Background(), nil, sc, p, r, writeOpts{})
	if err != nil {
		t.Fatal(err)
	}
	checkStaged(t, r)
	if got := read(t, p); got != "DB_PASSWORD=s3cret\n" || mode(t, p) != 0o644 || res["mode"] != "0644" {
		t.Fatalf("file %q mode %04o result %v", got, mode(t, p), res)
	}
}

// sync and upload -r stage each file the same way, and the file gets its
// source's mode only once it is complete.
func TestSyncStagesPrivately(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0o022))
	sc := localSFTP(t)
	dir := t.TempDir()
	r := &peekReader{dir: dir, parts: []string{"PART1-secret\n", "PART2\n"}}
	if err := (sftpSide{cl: tcl, sc: sc, root: dir}).write(context.Background(), "id_key", r, syncFile{Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	checkStaged(t, r)
	p := filepath.Join(dir, "id_key")
	if read(t, p) != "PART1-secret\nPART2\n" || mode(t, p) != 0o600 {
		t.Fatalf("mode %04o", mode(t, p))
	}
}
