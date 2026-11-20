package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/rundir"
)

// stageHome points the run folder at a new folder and returns it.
func stageHome(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run")
	saved := rundir.Base
	rundir.Base = func() (string, error) { return dir, nil }
	t.Cleanup(func() { rundir.Base = saved })
	return dir
}

// sealedFile writes three chunks and a bit of SQL and seals them.
func sealedFile(t *testing.T) (string, []byte, *backupSeal) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "b.sql")
	b := bytes.Repeat([]byte("INSERT INTO t VALUES (1);\n"), (3*sealChunk+500)/26)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	seal, _ := sealOf(t, path)
	return path, b, seal
}

func stagedCopies(t *testing.T, dir string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "restore-*.tmp"))
	return m
}

// The Audit case: a later chunk changes after the seal. The restore
// target gets nothing at all, so the database is untouched.
func TestRestoreStagedChangedLaterChunkSendsNothing(t *testing.T) {
	dir := stageHome(t)
	path, orig, seal := sealedFile(t)
	changed := append([]byte(nil), orig...)
	copy(changed[2*sealChunk+100:], "DROP DATABASE shop; --")
	os.WriteFile(path, changed, 0o600)
	got := 0
	err := restoreStaged(tcl, t.Context(), path, seal, func(r io.Reader) error {
		n, err := io.Copy(io.Discard, r)
		got += int(n)
		return err
	})
	if e := toErr(err); err == nil || e.Code != "FILE_CHANGED" {
		t.Fatalf("want FILE_CHANGED, got %v", err)
	}
	if got != 0 {
		t.Errorf("the restore target got %d bytes, want 0", got)
	}
	if l := stagedCopies(t, dir); len(l) != 0 {
		t.Errorf("left behind: %v", l)
	}
}

// The copy is made O_EXCL, mode 0600, in the checked run folder.
func TestRestoreStagedCopyIsPrivate(t *testing.T) {
	dir := stageHome(t)
	path, orig, seal := sealedFile(t)
	var got []byte
	err := restoreStaged(tcl, t.Context(), path, seal, func(r io.Reader) (err error) {
		l := stagedCopies(t, dir)
		if len(l) != 1 {
			t.Fatalf("copies in the run folder: %v", l)
		}
		fi, _ := os.Lstat(l[0])
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %o, want 600", fi.Mode().Perm())
		}
		got, err = io.ReadAll(r)
		return err
	})
	if err != nil || !bytes.Equal(got, orig) {
		t.Fatalf("restore: %v, %d bytes", err, len(got))
	}
	if l := stagedCopies(t, dir); len(l) != 0 {
		t.Errorf("left behind after success: %v", l)
	}
}

func TestRestoreStagedRefusesAnUnsafeFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the folder is in the user's own LocalAppData")
	}
	path, _, seal := sealedFile(t)
	root := t.TempDir()
	real := filepath.Join(root, "real")
	os.Mkdir(real, 0o700)
	link := filepath.Join(root, "link")
	os.Symlink(real, link)
	wide := filepath.Join(root, "wide")
	os.Mkdir(wide, 0o700)
	os.Chmod(wide, 0o777)
	saved := rundir.Base
	t.Cleanup(func() { rundir.Base = saved })
	for name, d := range map[string]string{"symlink": link, "mode 777": wide} {
		rundir.Base = func() (string, error) { return d, nil }
		called := false
		err := restoreStaged(tcl, t.Context(), path, seal, func(io.Reader) error { called = true; return nil })
		if err == nil || called {
			t.Errorf("%s: want a refusal before the restore, got %v", name, err)
		}
		if l := stagedCopies(t, real); len(l) != 0 {
			t.Errorf("%s: a copy went through the link: %v", name, l)
		}
	}
}

// Every way out removes the copy: an error of the restore, a cancel.
func TestRestoreStagedRemovesTheCopy(t *testing.T) {
	dir := stageHome(t)
	path, _, seal := sealedFile(t)
	boom := errors.New("boom")
	ctx, cancel := context.WithCancel(t.Context())
	for name, fn := range map[string]func(io.Reader) error{
		"an error": func(io.Reader) error { return boom },
		"a cancel": func(r io.Reader) error {
			cancel() // what the first Ctrl-C does (signalContext)
			io.CopyN(io.Discard, r, 10)
			return ctx.Err()
		},
	} {
		if err := restoreStaged(tcl, ctx, path, seal, fn); err == nil {
			t.Errorf("%s: want the error", name)
		}
		if l := stagedCopies(t, dir); len(l) != 0 {
			t.Errorf("%s: left behind: %v", name, l)
		}
	}
	// cancelled before the copy: no restore, no copy
	called := false
	if err := restoreStaged(tcl, ctx, path, seal, func(io.Reader) error { called = true; return nil }); err == nil || called {
		t.Errorf("a cancelled restore ran: %v", err)
	}
	if l := stagedCopies(t, dir); len(l) != 0 {
		t.Errorf("cancelled: left behind: %v", l)
	}
}

// The restore reads the verified copy through its open descriptor: the
// path replaced after the check changes nothing.
func TestRestoreStagedReadsTheVerifiedCopy(t *testing.T) {
	stageHome(t)
	path, orig, seal := sealedFile(t)
	saved := afterStage
	afterStage = func(staged string) {
		os.Remove(staged)
		os.WriteFile(staged, []byte("COPY t TO PROGRAM 'id';\n"), 0o600)
		os.WriteFile(path, []byte("COPY t TO PROGRAM 'id';\n"), 0o600)
	}
	t.Cleanup(func() { afterStage = saved })
	var got []byte
	err := restoreStaged(tcl, t.Context(), path, seal, func(r io.Reader) (err error) {
		got, err = io.ReadAll(r)
		return err
	})
	if err != nil || !bytes.Equal(got, orig) {
		t.Fatalf("restored %d bytes (%v); want the %d verified ones", len(got), err, len(orig))
	}
}

func TestRestoreStagedSweepsLeftovers(t *testing.T) {
	dir := stageHome(t)
	os.MkdirAll(dir, 0o700)
	old := filepath.Join(dir, "restore-0123.tmp")
	os.WriteFile(old, []byte("old"), 0o600)
	past := time.Now().Add(-2 * rundir.Stale)
	os.Chtimes(old, past, past)
	path, _, seal := sealedFile(t)
	if err := restoreStaged(tcl, t.Context(), path, seal, func(io.Reader) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(old); err == nil {
		t.Error("the leftover of an earlier run stayed")
	}
}

func TestRestoreStagedNoSpace(t *testing.T) {
	dir := stageHome(t)
	path, orig, seal := sealedFile(t)
	saved := restoreFree
	restoreFree = func(string) (uint64, error) { return 10, nil }
	t.Cleanup(func() { restoreFree = saved })
	called := false
	err := restoreStaged(tcl, t.Context(), path, seal, func(io.Reader) error { called = true; return nil })
	e := toErr(err)
	if err == nil || e.Code != "RESTORE_SPACE_MISSING" || called {
		t.Fatalf("want RESTORE_SPACE_MISSING before the restore, got %v", err)
	}
	if !strings.Contains(e.Hint, dir) || !strings.Contains(e.Hint, strconv.Itoa(len(orig))) {
		t.Errorf("the hint names neither the folder nor the bytes: %q", e.Hint)
	}
	if l := stagedCopies(t, dir); len(l) != 0 {
		t.Errorf("left behind: %v", l)
	}
}
