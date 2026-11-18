package storex

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/jlaffaye/ftp"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// mkdir, mv and chmod on the file servers (SFTP, FTP, WebDAV, SMB): they
// have real folders, and a move is one rename on the server.

// SFTP

func (b *sftpBucket) Lookup(_ context.Context, rel string) (Object, bool, error) {
	r := strings.Trim(rel, "/")
	p, err := b.path(r)
	if err != nil {
		return Object{}, false, err
	}
	fi, err := b.c.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return Object{}, false, nil
	}
	if err != nil {
		return Object{}, false, sftpErr(err)
	}
	return entry(r, fi), true, nil
}

func (b *sftpBucket) Mkdir(ctx context.Context, rel string) (bool, error) {
	r, err := cleanRel(rel)
	if err != nil {
		return false, err
	}
	o, found, err := b.Lookup(ctx, r)
	if err != nil || found && o.Dir {
		return found, err
	}
	if found {
		return false, fileInTheWay(r)
	}
	p, _ := b.path(r)
	return false, sftpErr(b.c.MkdirAll(p))
}

// Move renames on the server. A plain SFTP rename never replaces dst; with
// Overwrite, the posix-rename extension does it in one step, and a server
// without it gets the old file moved aside first (renameOver).
func (b *sftpBucket) Move(ctx context.Context, src, dst string, o MoveOpts) (Moved, error) {
	m, err := checkMove(ctx, b, src, dst, o, "")
	if err != nil || o.DryRun {
		return m, err
	}
	s, d := strings.Trim(src, "/"), strings.Trim(dst, "/")
	ps, _ := b.path(s)
	pd, _ := b.path(d)
	if err := b.c.MkdirAll(path.Dir(pd)); err != nil {
		return m, sftpErr(err)
	}
	if !m.Replaced {
		return m, sftpErr(b.c.Rename(ps, pd))
	}
	if err := b.c.PosixRename(ps, pd); err == nil {
		return m, nil
	}
	return m, renameOver(b.c.Rename, b.c.Remove, sftpErr, ps, pd, s, d)
}

func (b *sftpBucket) Mode(_ context.Context, rel string) (fs.FileMode, error) {
	r, err := cleanRel(rel)
	if err != nil {
		return 0, err
	}
	p, _ := b.path(r)
	fi, err := b.c.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return 0, NotThere(r)
	}
	if err != nil {
		return 0, sftpErr(err)
	}
	return fi.Mode(), nil
}

func (b *sftpBucket) Chmod(_ context.Context, rel string, mode fs.FileMode) error {
	r, err := cleanRel(rel)
	if err != nil {
		return err
	}
	p, _ := b.path(r)
	err = b.c.Chmod(p, mode)
	if errors.Is(err, os.ErrNotExist) {
		return NotThere(r)
	}
	return sftpErr(err)
}

// FTP

func (b *ftpBucket) Lookup(_ context.Context, rel string) (Object, bool, error) {
	r := strings.Trim(rel, "/")
	p, err := b.path(r)
	if err != nil {
		return Object{}, false, err
	}
	entries, err := b.c.List(path.Dir(p))
	if err != nil {
		if isMissingDir(err) {
			return Object{}, false, nil
		}
		return Object{}, false, ftpStepErr("LIST", err)
	}
	for _, e := range entries {
		if e.Name != path.Base(p) {
			continue
		}
		if e.Type == ftp.EntryTypeFolder {
			return Object{Key: r + "/", Dir: true, Modified: e.Time.UTC()}, true, nil
		}
		return Object{Key: r, Size: int64(e.Size), Modified: e.Time.UTC()}, true, nil
	}
	// a listing may leave files out (many servers hide names that start
	// with a dot): SIZE answers for a file that is there
	if n, err := b.c.FileSize(p); err == nil {
		return Object{Key: r, Size: n}, true, nil
	}
	return Object{}, false, nil
}

// mkdirs makes dir and its parents; "already there" answers are fine.
// It returns the last error, for when dir is still not there.
func (b *ftpBucket) mkdirs(dir string) error {
	var last error
	cur := ""
	for _, part := range strings.Split(strings.Trim(dir, "/"), "/") {
		if part == "" {
			continue
		}
		cur += "/" + part
		last = b.c.MakeDir(cur)
	}
	return last
}

func (b *ftpBucket) Mkdir(ctx context.Context, rel string) (bool, error) {
	r, err := cleanRel(rel)
	if err != nil {
		return false, err
	}
	o, found, err := b.Lookup(ctx, r)
	if err != nil || found && o.Dir {
		return found, err
	}
	if found {
		return false, fileInTheWay(r)
	}
	p, _ := b.path(r)
	merr := b.mkdirs(p)
	if o, found, err = b.Lookup(ctx, r); err != nil || found && o.Dir {
		return false, err
	}
	if merr == nil {
		merr = errors.New("the server made no folder")
	}
	return false, ftpErr(merr, driver.Target{})
}

// Move renames on the server (RNFR, RNTO). With Overwrite, a server that
// does not rename over a file gets the old one moved aside first
// (renameOver).
func (b *ftpBucket) Move(ctx context.Context, src, dst string, o MoveOpts) (Moved, error) {
	m, err := checkMove(ctx, b, src, dst, o, "")
	if err != nil || o.DryRun {
		return m, err
	}
	s, d := strings.Trim(src, "/"), strings.Trim(dst, "/")
	ps, _ := b.path(s)
	pd, _ := b.path(d)
	if dir := path.Dir(pd); dir != "/" {
		_ = b.mkdirs(dir) // a folder that cannot be made fails the rename
	}
	err = b.c.Rename(ps, pd)
	if err == nil || !m.Replaced {
		return m, ftpStepErr("RNFR/RNTO", err)
	}
	return m, renameOver(b.c.Rename, b.c.Delete, func(err error) error { return ftpErr(err, driver.Target{}) }, ps, pd, s, d)
}

func (r *ftpReconnect) Lookup(ctx context.Context, rel string) (Object, bool, error) {
	o, found, err := r.ftpBucket.Lookup(ctx, rel)
	if err != nil && r.again(&err) {
		return r.ftpBucket.Lookup(ctx, rel)
	}
	return o, found, err
}

// WebDAV

func (b *davBucket) Lookup(ctx context.Context, rel string) (Object, bool, error) {
	r := strings.Trim(rel, "/")
	if err := CheckKey(r); err != nil {
		return Object{}, false, err
	}
	u, err := b.url(r, false)
	if err != nil {
		return Object{}, false, err
	}
	got, err := b.propfind(ctx, u, "0")
	if oe, ok := err.(*out.Error); ok && oe.Code == "OBJECT_NOT_FOUND" {
		return Object{}, false, nil
	}
	if err != nil {
		return Object{}, false, err
	}
	if len(got) == 0 {
		return Object{}, false, nil
	}
	o := got[0]
	if o.Dir {
		return Object{Key: r + "/", Dir: true, Modified: o.Modified}, true, nil
	}
	o.Key = r
	return o, true, nil
}

func (b *davBucket) Mkdir(ctx context.Context, rel string) (bool, error) {
	r, err := cleanRel(rel)
	if err != nil {
		return false, err
	}
	o, found, err := b.Lookup(ctx, r)
	if err != nil || found && o.Dir {
		return found, err
	}
	if found {
		return false, fileInTheWay(r)
	}
	return false, b.mkdirs(ctx, r)
}

// Move is one MOVE request. Overwrite: F makes the server refuse to
// replace dst (412) even when it appeared after komando looked.
func (b *davBucket) Move(ctx context.Context, src, dst string, o MoveOpts) (Moved, error) {
	m, err := checkMove(ctx, b, src, dst, o, "")
	if err != nil || o.DryRun {
		return m, err
	}
	s, d := strings.Trim(src, "/"), strings.Trim(dst, "/")
	if err := b.mkdirs(ctx, path.Dir(d)); err != nil {
		return m, err
	}
	from, _ := b.url(s, m.Folder)
	to, _ := b.url(d, m.Folder)
	req, err := b.request(ctx, "MOVE", from, nil)
	if err != nil {
		return m, err
	}
	req.Header.Set("Destination", to.String())
	req.Header.Set("Overwrite", map[bool]string{true: "T", false: "F"}[m.Replaced])
	resp, err := do(b.c, "webdav", req, http.StatusCreated, http.StatusNoContent, http.StatusPreconditionFailed)
	if err != nil {
		return m, err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusPreconditionFailed {
		return m, fileInTheWay(d)
	}
	return m, nil
}

// SMB

func (b *smbBucket) Lookup(ctx context.Context, rel string) (Object, bool, error) {
	r := strings.Trim(rel, "/")
	p, err := b.path(r)
	if err != nil {
		return Object{}, false, err
	}
	fi, err := b.fs(ctx).Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return Object{}, false, nil
	}
	if err != nil {
		return Object{}, false, smbErr(err)
	}
	return entry(r, fi), true, nil
}

func (b *smbBucket) Mkdir(ctx context.Context, rel string) (bool, error) {
	r, err := cleanRel(rel)
	if err != nil {
		return false, err
	}
	o, found, err := b.Lookup(ctx, r)
	if err != nil || found && o.Dir {
		return found, err
	}
	if found {
		return false, fileInTheWay(r)
	}
	p, _ := b.path(r)
	return false, smbErr(b.fs(ctx).MkdirAll(p))
}

// Move renames on the share. SMB never renames over a file: with
// Overwrite the old one is moved aside first, and back if the rename
// fails, so dst is never lost to a failed move (renameOver).
func (b *smbBucket) Move(ctx context.Context, src, dst string, o MoveOpts) (Moved, error) {
	m, err := checkMove(ctx, b, src, dst, o, "")
	if err != nil || o.DryRun {
		return m, err
	}
	share := b.fs(ctx)
	s, d := strings.Trim(src, "/"), strings.Trim(dst, "/")
	ps, _ := b.path(s)
	pd, _ := b.path(d)
	if dir := path.Dir(pd); dir != "." {
		if err := share.MkdirAll(dir); err != nil {
			return m, smbErr(err)
		}
	}
	if !m.Replaced {
		err := share.Rename(ps, pd)
		if errors.Is(err, os.ErrExist) {
			return m, fileInTheWay(d)
		}
		return m, smbErr(err)
	}
	return m, renameOver(share.Rename, share.Remove, smbErr, ps, pd, s, d)
}
