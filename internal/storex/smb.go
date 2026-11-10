package storex

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// smbFS is the part of a mounted share that smbBucket uses. Paths are
// relative to the share, with / between the parts; "" is the share itself.
type smbFS interface {
	ReadDir(dir string) ([]os.FileInfo, error)
	Stat(name string) (os.FileInfo, error)
	Open(name string) (io.ReadCloser, error)
	// Create makes or empties a file for writing.
	Create(name string) (io.WriteCloser, error)
	MkdirAll(dir string) error
	// Rename fails with os.ErrExist when to is already there.
	Rename(from, to string) error
	Remove(name string) error
}

// smbBucket is a folder on an SMB share: a Windows file server, Samba, a
// NAS or Azure Files.
type smbBucket struct {
	fs     func(ctx context.Context) smbFS // the share, for one call
	prefix string
	close  func() error
}

// OpenSMB logs in to an smb:// conn and mounts its share. dial is nil for a
// direct connection. Every message is signed (the session key comes from
// the password, so a server that does not know it cannot answer), and the
// server encrypts the session or the share when it is set up to (SMB 3).
// A guest login cannot sign and is refused.
func OpenSMB(ctx context.Context, t driver.Target, password string, dial DialFunc, timeout time.Duration) (Bucket, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: timeout}).DialContext
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	conn, err := dial(ctx, "tcp", t.Address)
	if err != nil {
		return nil, smbLoginErr(err, t)
	}
	d := &smb2.Dialer{
		Negotiator: smb2.Negotiator{RequireMessageSigning: true},
		Initiator:  &smb2.NTLMInitiator{User: t.User, Password: password, Domain: t.Domain},
	}
	s, err := d.DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, smbLoginErr(err, t)
	}
	host, _, _ := net.SplitHostPort(t.Address)
	sh, err := s.WithContext(ctx).Mount(`\\` + host + `\` + t.Bucket)
	if err != nil {
		_ = s.Logoff()
		conn.Close()
		return nil, smbLoginErr(err, t)
	}
	b := &smbBucket{
		fs:     func(ctx context.Context) smbFS { return shareFS{sh.WithContext(ctx)} },
		prefix: t.Prefix,
	}
	b.close = smbCloser(timeout, conn,
		func(ctx context.Context) error { return sh.WithContext(ctx).Umount() },
		func(ctx context.Context) error { return s.WithContext(ctx).Logoff() })
	return b, nil
}

// smbCloser says goodbye to the server with each step, all within timeout
// (10s when there is none), then closes conn. go-smb2 waits on its context
// for each answer, so a server that stopped answering would otherwise keep
// komando from exiting.
func smbCloser(timeout time.Duration, conn io.Closer, steps ...func(context.Context) error) func() error {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		for _, step := range steps {
			_ = step(ctx)
		}
		return conn.Close()
	}
}

// shareFS is a mounted go-smb2 share as an smbFS.
type shareFS struct{ s *smb2.Share }

func (f shareFS) ReadDir(dir string) ([]os.FileInfo, error) { return f.s.ReadDir(dir) }
func (f shareFS) Stat(name string) (os.FileInfo, error)     { return f.s.Stat(name) }
func (f shareFS) MkdirAll(dir string) error                 { return f.s.MkdirAll(dir, 0o755) }
func (f shareFS) Rename(from, to string) error              { return f.s.Rename(from, to) }
func (f shareFS) Remove(name string) error                  { return f.s.Remove(name) }

// Open and Create return a nil interface on error, never a nil *smb2.File.
func (f shareFS) Open(name string) (io.ReadCloser, error) {
	fh, err := f.s.Open(name)
	if err != nil {
		return nil, err
	}
	return fh, nil
}

func (f shareFS) Create(name string) (io.WriteCloser, error) {
	fh, err := f.s.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return fh, nil
}

func (b *smbBucket) Close() error {
	if b.close != nil {
		return b.close()
	}
	return nil
}

// path is rel inside the conn's folder, relative to the share.
func (b *smbBucket) path(rel string) (string, error) {
	return keyIn(b.prefix, rel)
}

func (b *smbBucket) List(ctx context.Context, prefix string, recursive bool, limit int) ([]Object, bool, error) {
	if strings.Trim(prefix, "/") != "" {
		if _, err := keyIn(b.prefix, prefix); err != nil {
			return nil, false, err
		}
	}
	fs := b.fs(ctx)
	root := strings.TrimSuffix(b.prefix+strings.Trim(prefix, "/"), "/")
	objs := []Object{}
	queue := []string{root}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		fis, err := fs.ReadDir(dir)
		if err != nil {
			if dir == root && errors.Is(err, os.ErrNotExist) {
				return nil, false, FolderNotFound(prefix)
			}
			return nil, false, smbErr(err)
		}
		sort.Slice(fis, func(i, j int) bool { return fis[i].Name() < fis[j].Name() })
		for _, fi := range fis {
			if limit > 0 && len(objs) >= limit {
				return objs, true, nil
			}
			full := path.Join(dir, fi.Name())
			o := Object{Key: strings.TrimPrefix(full, b.prefix), Size: fi.Size(), Modified: fi.ModTime().UTC()}
			if fi.IsDir() {
				o.Key, o.Size, o.Dir = o.Key+"/", 0, true
				if recursive {
					queue = append(queue, full)
				}
			}
			objs = append(objs, o)
		}
	}
	return objs, false, nil
}

func (b *smbBucket) Stat(ctx context.Context, rel string) (Object, error) {
	p, err := b.path(rel)
	if err != nil {
		return Object{}, err
	}
	fi, err := b.fs(ctx).Stat(p)
	if err != nil {
		return Object{}, smbErr(err)
	}
	if fi.IsDir() {
		return Object{}, isFolder(rel)
	}
	return Object{Key: rel, Size: fi.Size(), Modified: fi.ModTime().UTC()}, nil
}

func (b *smbBucket) Exists(ctx context.Context, key string) (bool, error) {
	p, err := b.path(key)
	if err != nil {
		return false, err
	}
	if _, err := b.fs(ctx).Stat(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, smbErr(err)
	}
	return true, nil
}

func (b *smbBucket) Get(ctx context.Context, key string, w io.Writer) (int64, error) {
	p, err := b.path(key)
	if err != nil {
		return 0, err
	}
	fs := b.fs(ctx)
	if fi, err := fs.Stat(p); err != nil {
		return 0, smbErr(err)
	} else if fi.IsDir() {
		return 0, isFolder(key)
	}
	f, err := fs.Open(p)
	if err != nil {
		return 0, smbErr(err)
	}
	defer f.Close()
	n, err := io.Copy(w, f)
	return n, smbErr(err)
}

// Put writes a temporary file next to key and renames it into place, so a
// failed upload never leaves half a file under the real name.
func (b *smbBucket) Put(ctx context.Context, key string, r io.Reader, _ int64, _ string) error {
	p, err := b.path(key)
	if err != nil {
		return err
	}
	fs := b.fs(ctx)
	if fi, err := fs.Stat(p); err == nil && fi.IsDir() {
		return isFolder(key) // never moved aside like an old file
	}
	if dir := path.Dir(p); dir != "." {
		if err := fs.MkdirAll(dir); err != nil {
			return smbErr(err)
		}
	}
	tmp := path.Join(path.Dir(p), ".komando-upload-"+path.Base(p))
	f, err := fs.Create(tmp)
	if err != nil {
		return smbErr(err)
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		_ = fs.Remove(tmp)
		return smbErr(err)
	}
	if err := f.Close(); err != nil {
		_ = fs.Remove(tmp)
		return smbErr(err)
	}
	return smbReplace(fs, tmp, p)
}

// smbReplace renames tmp to p. SMB does not rename over a file, so an old
// file is moved aside first and removed only once the new one is in place;
// if that fails, the old file goes back.
func smbReplace(fs smbFS, tmp, p string) error {
	err := fs.Rename(tmp, p)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		_ = fs.Remove(tmp)
		return smbErr(err)
	}
	old := path.Join(path.Dir(p), ".komando-old-"+path.Base(p))
	_ = fs.Remove(old) // left by an upload that was cut off
	if err := fs.Rename(p, old); err != nil {
		_ = fs.Remove(tmp)
		return smbErr(err)
	}
	if err := fs.Rename(tmp, p); err != nil {
		if rerr := fs.Rename(old, p); rerr != nil {
			return out.Errf(out.ExitRemote, "UPLOAD_NOT_RENAMED",
				"the old file is on the share as "+old+" and the new content as "+tmp+": rename one of them by hand",
				"could not rename the upload into place: %v", err)
		}
		_ = fs.Remove(tmp)
		return smbErr(err)
	}
	_ = fs.Remove(old)
	return nil
}

func (b *smbBucket) Remove(ctx context.Context, key string) error {
	p, err := b.path(key)
	if err != nil {
		return err
	}
	fs := b.fs(ctx)
	fi, err := fs.Stat(p)
	if err != nil {
		return smbErr(err)
	}
	if fi.IsDir() {
		return out.Usage("%q is a folder; rm deletes files only", key)
	}
	return smbErr(fs.Remove(p))
}

func (b *smbBucket) Link(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, noLinks("SMB")
}
