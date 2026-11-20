package cli

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/rundir"
	"github.com/sgnd/komando/internal/tmpclean"
)

// restoreFree is the free space of the run folder; tests replace it.
var restoreFree = rundir.Free

// afterStage runs between the check of the copy and the restore; only a
// test changes the files there.
var afterStage = func(string) {}

// restoreStaged makes a restore atomic: it copies the backup, as stored,
// into a private file in komando's run folder while checking every chunk
// against the seal, and hands fn a reader of that copy only once the
// whole copy matched. A file changed anywhere after the check stops with
// FILE_CHANGED before fn runs, so the database gets no byte. fn reads the
// copy through the descriptor that wrote it, never by its path, and the
// copy is removed on every way out (a second Ctrl-C: tmpclean).
func restoreStaged(cl *call, ctx context.Context, from string, seal *backupSeal, fn func(io.Reader) error) error {
	if err := guardBackupFile(cl, from); err != nil {
		return err
	}
	src, err := os.Open(from)
	if err != nil {
		return localFileErr("FILE_NOT_FOUND", err, "")
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil {
		return localFileErr("FILE_NOT_FOUND", err, "")
	}
	dir, err := rundir.Dir()
	if err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "fix the folder as the message says, then restore again", "%v", err)
	}
	rundir.Sweep(dir, "restore")
	need := uint64(fi.Size()) //nolint:gosec // a file's size is never negative
	if free, err := restoreFree(dir); err == nil && free < need {
		return noRestoreSpace(dir, need, from)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := rundir.Create(dir, "restore")
	if err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "check that "+dir+" is writable", "%s: %v", "cannot make the restore's copy", err)
	}
	forget := tmpclean.Add(f.Name())
	defer func() {
		f.Close()
		os.Remove(f.Name())
		forget()
	}()
	sr := &sealReader{r: src, seal: seal, verify: true, buf: make([]byte, sealChunk)}
	if _, err := io.Copy(f, ctxReader{ctx, sr}); err != nil {
		switch {
		case seal.changed:
			return backupChanged(from)
		case errors.Is(err, syscall.ENOSPC):
			return noRestoreSpace(dir, need, from)
		case ctx.Err() != nil:
			return ctx.Err()
		}
		return out.Errf(out.ExitError, "FILE_ERROR", "check that "+dir+" is writable", "%s: %v", "cannot make the restore's copy", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "check that "+dir+" is writable", "%s: %v", "cannot read the restore's copy", err)
	}
	afterStage(f.Name())
	var r io.Reader = f
	if strings.HasSuffix(from, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return out.Errf(out.ExitUsage, "BAD_FILE", "the file ends in .gz but is not gzip data", "%v", err)
		}
		defer gz.Close()
		r = gz
	}
	return fn(r)
}

func noRestoreSpace(dir string, need uint64, from string) *out.Error {
	return out.Errf(out.ExitNotFound, "RESTORE_SPACE_MISSING",
		fmt.Sprintf("free %d bytes in %s (komando checks a private copy of the backup there before the database is touched), then restore again: `komando db restore CONN --from %s`", need, dir, from),
		"not enough free space for the restore's copy; nothing was sent to the database")
}

// ctxReader stops a copy once ctx is cancelled (the first Ctrl-C).
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
