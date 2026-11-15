package storex

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	krfs "github.com/kr/fs"
	"github.com/pkg/sftp"

	"github.com/sgnd/komando/internal/out"
)

// sftpBucket is a folder on an SFTP server: file access over SSH, for
// accounts that have no shell (typical for web hosting).
type sftpBucket struct {
	c      *sftp.Client
	prefix string
	close  func() error
}

// NewSFTP wraps an SFTP session; close also closes its SSH connection.
func NewSFTP(c *sftp.Client, prefix string, close func() error) Bucket {
	return &sftpBucket{c: c, prefix: prefix, close: close}
}

func (b *sftpBucket) Close() error {
	b.c.Close()
	if b.close != nil {
		return b.close()
	}
	return nil
}

// An SFTP server sends a folder in whatever order its disk keeps it.
// SortedReadDir and SortedWalk sort each folder by name, so a listing reads
// like ls and the same folder lists the same way every time.

// SortedReadDir is c.ReadDir sorted by name.
func SortedReadDir(c *sftp.Client, dir string) ([]os.FileInfo, error) {
	fis, err := c.ReadDir(dir)
	sort.Slice(fis, func(i, j int) bool { return fis[i].Name() < fis[j].Name() })
	return fis, err
}

// SortedWalk is c.Walk with each folder sorted by name.
func SortedWalk(c *sftp.Client, root string) *krfs.Walker {
	return krfs.WalkFS(root, sortedDirs{c})
}

type sortedDirs struct{ *sftp.Client }

func (s sortedDirs) ReadDir(dir string) ([]os.FileInfo, error) { return SortedReadDir(s.Client, dir) }

func (b *sftpBucket) path(rel string) (string, error) {
	k, err := keyIn(b.prefix, rel)
	return "/" + k, err
}

func (b *sftpBucket) List(_ context.Context, prefix string, recursive bool, limit int) ([]Object, bool, error) {
	if strings.Trim(prefix, "/") != "" {
		if _, err := keyIn(b.prefix, prefix); err != nil {
			return nil, false, err
		}
	}
	root := "/" + b.prefix + strings.Trim(prefix, "/")
	objs := []Object{}
	add := func(full string, fi fs.FileInfo) bool {
		if limit > 0 && len(objs) >= limit {
			return false
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(full, "/"+b.prefix), "/")
		o := Object{Key: rel, Size: fi.Size(), Modified: fi.ModTime().UTC()}
		if fi.IsDir() {
			o.Key, o.Size, o.Dir = rel+"/", 0, true
		}
		objs = append(objs, o)
		return true
	}
	if recursive {
		w := SortedWalk(b.c, root)
		for w.Step() {
			if err := w.Err(); err != nil {
				if errors.Is(err, os.ErrNotExist) && w.Path() == root {
					return nil, false, FolderNotFound(prefix)
				}
				return nil, false, sftpErr(err)
			}
			if w.Path() == root {
				continue
			}
			if !add(w.Path(), w.Stat()) {
				return objs, true, nil
			}
		}
		return objs, false, nil
	}
	entries, err := SortedReadDir(b.c, root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, FolderNotFound(prefix)
	}
	if err != nil {
		return nil, false, sftpErr(err)
	}
	for _, e := range entries {
		if !add(path.Join(root, e.Name()), e) {
			return objs, true, nil
		}
	}
	return objs, false, nil
}

func (b *sftpBucket) Get(ctx context.Context, key string, w io.Writer) (int64, error) {
	p, err := b.path(key)
	if err != nil {
		return 0, err
	}
	f, err := b.c.Open(p)
	if err != nil {
		return 0, sftpErr(err)
	}
	defer f.Close()
	n, err := io.Copy(CtxWriter(ctx, w), f)
	return n, sftpErr(err)
}

func (b *sftpBucket) Exists(_ context.Context, key string) (bool, error) {
	p, err := b.path(key)
	if err != nil {
		return false, err
	}
	if _, err := b.c.Stat(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, sftpErr(err)
	}
	return true, nil
}

// Put writes a temporary file (mode 0600, in a private folder) and renames
// it into place.
func (b *sftpBucket) Put(ctx context.Context, key string, r io.Reader, _ int64, _ string) error {
	p, err := b.path(key)
	if err != nil {
		return err
	}
	if err := b.c.MkdirAll(path.Dir(p)); err != nil {
		return sftpErr(err)
	}
	// a folder of its own under a name no one can guess, made exclusively
	// (mkdir never follows a link), entered only by the SSH user: a link
	// another user planted is never written through, and the file is not
	// readable while it is written (pkg/sftp makes it at the server's
	// default mode until the chmod)
	d := path.Join(path.Dir(p), ".komando-upload-"+strings.ToLower(rand.Text()))
	if err := b.c.Mkdir(d); err != nil {
		return sftpErr(err)
	}
	_ = b.c.Chmod(d, 0o700) // some servers forbid modes; the name still cannot be guessed
	tmp := path.Join(d, path.Base(p))
	keep := false // the upload is only there: never remove it
	defer func() {
		if !keep {
			_ = b.c.Remove(tmp)
			_ = b.c.RemoveDirectory(d)
		}
	}()
	f, err := b.c.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		return sftpErr(err)
	}
	_ = f.Chmod(0o600)
	if _, err := io.Copy(f, CtxReader(ctx, r)); err != nil {
		f.Close()
		return sftpErr(err)
	}
	if err := f.Close(); err != nil {
		return sftpErr(err)
	}
	// keep the old file's permissions, or the server's usual 0644 for new ones
	mode := os.FileMode(0o644)
	if fi, err := b.c.Stat(p); err == nil {
		mode = fi.Mode().Perm()
	}
	_ = b.c.Chmod(tmp, mode)
	if err := b.c.PosixRename(tmp, p); err != nil {
		// servers without the posix-rename extension cannot rename over a
		// file: try a plain rename, then remove the old file only if it
		// exists, and once it is gone never delete the upload
		if err = b.c.Rename(tmp, p); err == nil {
			return nil
		}
		if _, serr := b.c.Stat(p); serr != nil {
			return sftpErr(err)
		}
		if rerr := b.c.Remove(p); rerr != nil {
			return sftpErr(err)
		}
		if rerr := b.c.Rename(tmp, p); rerr != nil {
			keep = true
			return out.Errf(out.ExitRemote, "UPLOAD_NOT_RENAMED",
				"the new content is on the server as "+tmp+": rename it by hand",
				"could not rename the upload into place: %v; the old file was removed", rerr)
		}
	}
	return nil
}

func (b *sftpBucket) Remove(_ context.Context, key string) error {
	p, err := b.path(key)
	if err != nil {
		return err
	}
	fi, err := b.c.Stat(p)
	if err != nil {
		return sftpErr(err)
	}
	if fi.IsDir() {
		return out.Usage("%q is a folder; rm deletes files only", key)
	}
	return sftpErr(b.c.Remove(p))
}

func (b *sftpBucket) Link(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, noLinks("SFTP")
}

func sftpErr(err error) error {
	if err == nil {
		return nil
	}
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
	}
	switch {
	case errors.Is(err, context.Canceled):
		return err // Ctrl-C: komando says CANCELLED
	case errors.Is(err, os.ErrNotExist):
		return out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list files with `komando storage list CONN [PREFIX]`", "file not found")
	case errors.Is(err, os.ErrPermission):
		return out.Errf(out.ExitConnect, "STORAGE_AUTH", "the account may not write or read here; check the folder in the conn URL", "permission denied")
	}
	return out.Errf(out.ExitRemote, "STORAGE_ERROR", "run `komando test TARGET` to check the conn", "%v", err)
}
