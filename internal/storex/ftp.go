package storex

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// ftpBucket is a folder on an FTP or FTPS (explicit TLS) server.
type ftpBucket struct {
	c      *ftp.ServerConn
	prefix string
}

// OpenFTP logs in to an ftp:// or ftps:// conn. dial is nil for a direct
// connection; through --via, the control and data connections both use it.
// When the server drops a connection in the middle of an operation, the
// returned Bucket logs in again once and repeats it (see ftpReconnect).
func OpenFTP(ctx context.Context, t driver.Target, password string, dial DialFunc, timeout time.Duration) (Bucket, error) {
	if dial == nil {
		d := &net.Dialer{Timeout: timeout}
		dial = d.DialContext
	}
	login := func() (*ftp.ServerConn, error) { return loginFTP(ctx, t, password, dial, timeout) }
	c, err := login()
	if err != nil {
		return nil, err
	}
	return &ftpReconnect{ftpBucket: &ftpBucket{c: c, prefix: t.Prefix}, login: login}, nil
}

// loginFTP opens one FTP session: the control connection, TLS, and the login.
// Each session gets its own TLS session cache.
func loginFTP(ctx context.Context, t driver.Target, password string, dial DialFunc, timeout time.Duration) (*ftp.ServerConn, error) {
	host, _, _ := net.SplitHostPort(t.Address)
	var tlsCfg *tls.Config
	if t.Secure {
		tlsCfg = &tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: t.TLS == "skip-verify",
			// many servers require data connections to resume the control
			// connection's TLS session
			ClientSessionCache: tls.NewLRUClientSessionCache(4),
		}
	}
	calls := 0
	opts := []ftp.DialOption{
		ftp.DialWithTimeout(timeout),
		ftp.DialWithContext(ctx),
		ftp.DialWithDialFunc(func(network, addr string) (net.Conn, error) {
			calls++
			// the library takes the data host from the control connection's IP,
			// which is unknown through an SSH or VPN hop: use the server name
			if h, p, err := net.SplitHostPort(addr); err == nil && (h == "<nil>" || h == "0.0.0.0") {
				addr = net.JoinHostPort(host, p)
			}
			c, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if calls == 1 {
				// control connection: the library upgrades it after AUTH TLS
				return fixedAddr{c, &net.TCPAddr{Port: 21}}, nil
			}
			if tlsCfg != nil { // data connections: the library leaves TLS to us
				return tls.Client(c, tlsCfg), nil
			}
			return c, nil
		}),
	}
	if tlsCfg != nil {
		opts = append(opts, ftp.DialWithExplicitTLS(tlsCfg))
	}
	c, err := ftp.Dial(t.Address, opts...)
	if err != nil {
		return nil, ftpErr(err, t)
	}
	if err := c.Login(t.User, password); err != nil {
		c.Quit()
		return nil, ftpErr(err, t)
	}
	return c, nil
}

// ftpReconnect repeats an operation once in a new session when the server
// dropped the connection (STORAGE_CONNECT: EOF, reset, broken pipe), never
// after an FTP error reply, a TLS or a timeout error. Only what is safe to
// repeat is repeated: a download that already wrote bytes, or an upload whose
// source cannot go back to its start, keeps the first error.
type ftpReconnect struct {
	*ftpBucket
	login func() (*ftp.ServerConn, error)
}

// again reports whether err is a dropped connection and a new session is open.
func (r *ftpReconnect) again(err error) bool {
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STORAGE_CONNECT" {
		return false
	}
	c, lerr := r.login()
	if lerr != nil {
		return false
	}
	_ = r.c.Quit() // the old session is broken; this only frees it
	r.c = c
	return true
}

func (r *ftpReconnect) List(ctx context.Context, prefix string, recursive bool, limit int) ([]Object, bool, error) {
	objs, more, err := r.ftpBucket.List(ctx, prefix, recursive, limit)
	if err != nil && r.again(err) {
		return r.ftpBucket.List(ctx, prefix, recursive, limit)
	}
	return objs, more, err
}

func (r *ftpReconnect) Get(ctx context.Context, key string, w io.Writer) (int64, error) {
	n, err := r.ftpBucket.Get(ctx, key, w)
	if err != nil && n == 0 && r.again(err) {
		return r.ftpBucket.Get(ctx, key, w)
	}
	return n, err
}

func (r *ftpReconnect) Exists(ctx context.Context, key string) (bool, error) {
	ok, err := r.ftpBucket.Exists(ctx, key)
	if err != nil && r.again(err) {
		return r.ftpBucket.Exists(ctx, key)
	}
	return ok, err
}

func (r *ftpReconnect) Stat(ctx context.Context, key string) (Object, error) {
	o, err := r.ftpBucket.Stat(ctx, key)
	if err != nil && r.again(err) {
		return r.ftpBucket.Stat(ctx, key)
	}
	return o, err
}

func (r *ftpReconnect) Put(ctx context.Context, key string, src io.Reader, size int64, contentType string) error {
	err := r.ftpBucket.Put(ctx, key, src, size, contentType)
	if err == nil {
		return nil
	}
	s, ok := src.(io.Seeker)
	if !ok {
		return err
	}
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STORAGE_CONNECT" {
		return err
	}
	if _, serr := s.Seek(0, io.SeekStart); serr != nil {
		return err
	}
	if !r.again(err) {
		return err
	}
	return r.ftpBucket.Put(ctx, key, src, size, contentType)
}

func (r *ftpReconnect) Remove(ctx context.Context, key string) error {
	err := r.ftpBucket.Remove(ctx, key)
	if err != nil && r.again(err) {
		err = r.ftpBucket.Remove(ctx, key)
		var oe *out.Error
		if errors.As(err, &oe) && oe.Code == "OBJECT_NOT_FOUND" {
			return nil // the first try removed it before the connection dropped
		}
	}
	return err
}

// fixedAddr hides the remote address of a connection made through a hop,
// whose IP the library would otherwise misuse.
type fixedAddr struct {
	net.Conn
	addr net.Addr
}

func (f fixedAddr) RemoteAddr() net.Addr { return f.addr }

func (b *ftpBucket) Close() error { return b.c.Quit() }

func (b *ftpBucket) path(rel string) (string, error) {
	k, err := keyIn(b.prefix, rel)
	return "/" + k, err
}

func (b *ftpBucket) List(_ context.Context, prefix string, recursive bool, limit int) ([]Object, bool, error) {
	if strings.Trim(prefix, "/") != "" {
		if _, err := keyIn(b.prefix, prefix); err != nil {
			return nil, false, err
		}
	}
	root := "/" + b.prefix + strings.Trim(prefix, "/")
	objs := []Object{}
	add := func(full string, e *ftp.Entry) bool {
		if limit > 0 && len(objs) >= limit {
			return false
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(full, "/"+b.prefix), "/")
		o := Object{Key: rel, Size: int64(e.Size), Modified: e.Time.UTC()}
		if e.Type == ftp.EntryTypeFolder {
			o.Key, o.Size, o.Dir = rel+"/", 0, true
		}
		objs = append(objs, o)
		return true
	}
	// walk lists dir sorted by name (a server sends it in any order) and,
	// with recursive, each folder in it right after the folder itself.
	// more is true when limit cut the listing short.
	var walk func(dir string) (more bool, err error)
	walk = func(dir string) (bool, error) {
		entries, err := b.c.List(dir)
		if err != nil {
			return false, err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		for _, e := range entries {
			if e.Name == "." || e.Name == ".." {
				continue
			}
			p := path.Join(dir, e.Name)
			if !add(p, e) {
				return true, nil
			}
			if recursive && e.Type == ftp.EntryTypeFolder {
				if more, err := walk(p); more || err != nil {
					return more, err
				}
			}
		}
		return false, nil
	}
	more, err := walk(root)
	if isMissingDir(err) {
		return nil, false, FolderNotFound(prefix)
	}
	if err != nil {
		return nil, false, ftpErr(err, driver.Target{})
	}
	return objs, more, nil
}

func (b *ftpBucket) Get(ctx context.Context, key string, w io.Writer) (int64, error) {
	p, err := b.path(key)
	if err != nil {
		return 0, err
	}
	r, err := b.c.Retr(p)
	if err != nil {
		return 0, ftpErr(err, driver.Target{})
	}
	defer r.Close()
	n, err := io.Copy(CtxWriter(ctx, w), r)
	return n, ftpErr(err, driver.Target{})
}

func (b *ftpBucket) Exists(_ context.Context, key string) (bool, error) {
	p, err := b.path(key)
	if err != nil {
		return false, err
	}
	if _, err := b.c.FileSize(p); err == nil {
		return true, nil
	} else if !isNotFound(err) && !isNotImplemented(err) {
		return false, ftpErr(err, driver.Target{})
	}
	// SIZE says no (or is not supported): confirm with a listing of the folder
	entries, err := b.c.List(path.Dir(p))
	if err != nil {
		// a missing folder is 550 on most servers, 501 on some
		if isNotFound(err) || isNotImplemented(err) {
			return false, nil
		}
		return false, ftpErr(err, driver.Target{})
	}
	for _, e := range entries {
		if e.Name == path.Base(p) && e.Type != ftp.EntryTypeFolder {
			return true, nil
		}
	}
	return false, nil
}

// isMissingDir: listing a folder that is not there is 550 on most servers,
// 450 or 501 ("No such directory") on others.
func isMissingDir(err error) bool {
	var te *textproto.Error
	return errors.As(err, &te) && (te.Code == ftp.StatusFileUnavailable || te.Code == ftp.StatusFileActionIgnored ||
		te.Code == ftp.StatusBadArguments && strings.Contains(strings.ToLower(te.Msg), "no such"))
}

func isNotImplemented(err error) bool {
	var te *textproto.Error
	return errors.As(err, &te) && (te.Code == ftp.StatusNotImplemented || te.Code == ftp.StatusCommandNotImplemented || te.Code == ftp.StatusBadArguments)
}

// Put uploads to a temporary name and renames it into place, so a failed
// upload never leaves half a file under the real name.
func (b *ftpBucket) Put(ctx context.Context, key string, r io.Reader, _ int64, _ string) error {
	p, err := b.path(key)
	if err != nil {
		return err
	}
	dir := path.Dir(p)
	if dir != "/" { // create missing folders; "already exists" errors are fine
		cur := ""
		for _, part := range strings.Split(strings.Trim(dir, "/"), "/") {
			cur += "/" + part
			_ = b.c.MakeDir(cur)
		}
	}
	tmp := path.Join(dir, ".komando-upload-"+path.Base(p))
	if err := b.c.Stor(tmp, CtxReader(ctx, r)); err != nil {
		_ = b.c.Delete(tmp)
		return ftpErr(err, driver.Target{})
	}
	if err := b.c.Rename(tmp, p); err != nil {
		// some servers refuse to rename over an existing file: remove the old
		// one only if it exists, and once it is gone never delete the upload
		exists, xerr := b.Exists(context.Background(), key)
		if xerr != nil || !exists {
			_ = b.c.Delete(tmp)
			return ftpErr(err, driver.Target{})
		}
		if derr := b.c.Delete(p); derr != nil {
			_ = b.c.Delete(tmp)
			return ftpErr(err, driver.Target{})
		}
		if rerr := b.c.Rename(tmp, p); rerr != nil {
			return out.Errf(out.ExitRemote, "UPLOAD_NOT_RENAMED",
				"the old file was removed; the new content is on the server as "+tmp+": rename it by hand",
				"could not rename the upload into place: %v", rerr)
		}
	}
	return nil
}

func (b *ftpBucket) Remove(_ context.Context, key string) error {
	p, err := b.path(key)
	if err != nil {
		return err
	}
	return ftpErr(b.c.Delete(p), driver.Target{})
}

func (b *ftpBucket) Link(context.Context, string, time.Duration) (*url.URL, error) {
	return nil, noLinks("FTP")
}

func noLinks(what string) error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED", "download the file with `komando storage download` and share it another way",
		"%s servers have no temporary download links", what)
}

func isNotFound(err error) bool {
	var te *textproto.Error
	return errors.As(err, &te) && te.Code == ftp.StatusFileUnavailable
}

func ftpErr(err error, t driver.Target) error {
	if err == nil {
		return nil
	}
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
	}
	if errors.Is(err, context.Canceled) {
		return err // Ctrl-C: komando says CANCELLED
	}
	var te *textproto.Error
	if errors.As(err, &te) {
		switch te.Code {
		case ftp.StatusNotLoggedIn:
			return out.Errf(out.ExitConnect, "STORAGE_AUTH", "check the user in the conn URL and its --password-ref", "login refused: %s", te.Msg)
		case ftp.StatusFileUnavailable:
			return out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list files with `komando storage list CONN [FOLDER]`", "%s", te.Msg)
		}
		return out.Errf(out.ExitRemote, "STORAGE_ERROR", "run `komando conn test NAME` to check the conn", "FTP %d: %s", te.Code, te.Msg)
	}
	if strings.Contains(err.Error(), "certificate") {
		return out.Errf(out.ExitConnect, "STORAGE_TLS", "if the server uses a self-signed certificate you trust, add ?tls=skip-verify to the conn URL", "%v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "check the address or raise --timeout", "%v", err)
	}
	where := t.Address
	if where == "" {
		where = "the server"
	}
	return out.Errf(out.ExitConnect, "STORAGE_CONNECT", "run `komando conn test NAME` to check reachability", "%s: %v", where, err)
}
