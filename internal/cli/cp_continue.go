package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"os"
	"path"
	"regexp"
	"strconv"
	"time"

	"github.com/pkg/sftp"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/storex"
)

// --continue: a copy that was cut off goes on where it stopped. The file
// at the destination is written in place (not under a temporary name), so
// a copy that stops again can be continued again. Before anything is
// added, the part already there is checked against the same part of the
// source (sha256); once the rest is in, the whole file is checked against
// the source. A destination that is longer, or differs, is never touched.

const continueUsage = "go on with a copy that was cut off: keep the part already at the destination when it matches the source, send the rest, then check the whole file (sha256)"

// resumeEnd is one side of a single-file copy that --continue can take up
// again: a file here, on a server or in a storage conn.
type resumeEnd interface {
	where() string // how messages name it: ./x, web1:/x, backups:x
	// size is the file's length; exists is false when there is none
	size(ctx context.Context) (n int64, exists bool, err error)
	// sumThere is the sha256 of the first n bytes (n < 0: all), worked out
	// where the file is (a server), so the bytes need not travel; ok is
	// false when it cannot be, and komando reads the bytes instead
	sumThere(ctx context.Context, n int64) (sum string, ok bool)
	openAt(ctx context.Context, off int64) (io.ReadCloser, error)
}

// resumeDst is the side --continue writes to.
type resumeDst interface {
	resumeEnd
	// canAppend says whether more can be added to the end of a file there
	canAppend() bool
	// notLink refuses a symbolic link: --continue writes in place, and
	// never through a link to another file
	notLink() error
	// appendAt writes r, n bytes, at off, the file's length now (0: a
	// new file)
	appendAt(ctx context.Context, off, n int64, r io.Reader) error
}

// resumed is what --continue did to one file.
type resumed struct {
	from  int64  // bytes already at the destination, kept
	bytes int64  // the file's length now
	sum   string // its sha256, checked against the source
}

// resumeCopy copies src to dst, going on from what dst already holds.
// --progress counts the kept part as done and label as the file.
func resumeCopy(ctx context.Context, src resumeEnd, dst resumeDst, label string) (resumed, error) {
	ss, ok, err := src.size(ctx)
	if err != nil {
		return resumed{}, err
	}
	if !ok {
		return resumed{}, out.Errf(out.ExitNotFound, "PATH_NOT_FOUND", "check the source path", "%s does not exist; nothing was changed", src.where())
	}
	if err := dst.notLink(); err != nil {
		return resumed{}, err
	}
	ds, there, err := dst.size(ctx)
	if err != nil {
		return resumed{}, err
	}
	if ds > ss {
		return resumed{}, resumeConflict(dst.where(), fmt.Sprintf("is longer than the source (%s, the source %s)", humanBytes(ds), humanBytes(ss)))
	}
	if ds > 0 && ds < ss && !dst.canAppend() {
		return resumed{}, out.Errf(out.ExitUsage, "RESUME_UNSUPPORTED", "run it again without --continue to copy the whole file: `komando cp SRC DST`",
			"%s cannot be continued: this kind of storage (S3, Google Cloud Storage, Azure Blob, WebDAV) stores a file whole and cannot add to one; nothing was changed", dst.where())
	}
	sh, dh := sha256.New(), sha256.New()
	srcAll := true // sh has seen every byte of the source so far
	if ds > 0 {
		a, here, err := prefixSum(ctx, src, ds, sh)
		if err != nil {
			return resumed{}, err
		}
		srcAll = here
		b, _, err := prefixSum(ctx, dst, ds, dh)
		if err != nil {
			return resumed{}, err
		}
		if a != b {
			return resumed{}, resumeConflict(dst.where(), fmt.Sprintf("differs from the source in its first %s", humanBytes(ds)))
		}
	}
	pp := progressFrom(ctx)
	pp.total(1, ss)
	pp.start(label)
	pp.skip(ds)
	if ds < ss || !there { // an empty source still makes its file
		r, err := src.openAt(ctx, ds)
		if err != nil {
			return resumed{}, err
		}
		var in io.Reader = r
		if srcAll {
			in = io.TeeReader(in, sh)
		}
		in = pp.reader(in)
		err = dst.appendAt(ctx, ds, ss-ds, storex.CtxReader(ctx, in))
		r.Close()
		if ctx.Err() != nil {
			return resumed{}, ctx.Err()
		}
		if err != nil {
			return resumed{}, err
		}
	}
	want := hex.EncodeToString(sh.Sum(nil))
	if !srcAll {
		if want, err = wholeSum(ctx, src); err != nil {
			return resumed{}, err
		}
	}
	got, err := wholeSum(ctx, dst)
	if err != nil {
		return resumed{}, err
	}
	n, _, err := dst.size(ctx)
	if err != nil {
		return resumed{}, err
	}
	if got != want {
		return resumed{}, out.Errf(out.ExitConflict, "RESUME_CONFLICT", "copy the whole file again without --continue (a download replaces a file here only with --overwrite): `komando cp SRC DST`",
			"%s does not match the source after the copy (sha256 %s, the source %s); it was left as it is", dst.where(), got, want)
	}
	pp.fileDone()
	return resumed{from: ds, bytes: n, sum: got}, nil
}

// fileChanged: a file changed while komando copied it; the next step is to
// run the same command again, which reads it anew.
func fileChanged(where, why string) error {
	return out.Errf(out.ExitConflict, "FILE_CHANGED", "run the same command again (`komando cp SRC DST --continue`): komando reads the file's length again",
		"%s %s; nothing was added", where, why)
}

func resumeConflict(where, why string) error {
	return out.Errf(out.ExitConflict, "RESUME_CONFLICT", "copy the whole file again without --continue (a download replaces a file here only with --overwrite): `komando cp SRC DST`",
		"%s %s, so --continue cannot go on from it; nothing was changed", where, why)
}

// prefixSum is the sha256 of the first n bytes of e: worked out where e is
// when it can be, else read here into h (here true; h goes on from there).
func prefixSum(ctx context.Context, e resumeEnd, n int64, h hash.Hash) (sum string, here bool, err error) {
	if s, ok := e.sumThere(ctx, n); ok {
		return s, false, nil
	}
	r, err := e.openAt(ctx, 0)
	if err != nil {
		return "", true, err
	}
	defer r.Close()
	got, err := io.Copy(h, storex.CtxReader(ctx, io.LimitReader(r, n)))
	if err != nil {
		return "", true, err
	}
	if got != n {
		return "", true, fileChanged(e.where(), "became shorter while komando read it")
	}
	return hex.EncodeToString(h.Sum(nil)), true, nil
}

// wholeSum is the sha256 of all of e.
func wholeSum(ctx context.Context, e resumeEnd) (string, error) {
	if s, ok := e.sumThere(ctx, -1); ok {
		return s, nil
	}
	r, err := e.openAt(ctx, 0)
	if err != nil {
		return "", err
	}
	defer r.Close()
	h := sha256.New()
	if _, err := io.Copy(h, storex.CtxReader(ctx, r)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// A file on this computer.

type localEnd struct {
	cl   *call // the command, for a destination: its writes are checked (guardLocalWrite)
	path string
	perm os.FileMode // a new file's mode
}

func (l localEnd) where() string { return l.path }

func (l localEnd) size(context.Context) (int64, bool, error) {
	fi, err := os.Stat(l.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return 0, false, nil
	case err != nil:
		e := localFileErr("", err, "")
		return 0, false, out.Errf(out.ExitError, "FILE_ERROR", e.Hint, "%s", e.Message)
	case fi.IsDir():
		return 0, false, out.Usage("%s is a folder; --continue takes one file", l.path)
	}
	return fi.Size(), true, nil
}

func (localEnd) sumThere(context.Context, int64) (string, bool) { return "", false }

func (l localEnd) openAt(_ context.Context, off int64) (io.ReadCloser, error) {
	f, err := os.Open(l.path)
	if err != nil {
		return nil, localFileErr("PATH_NOT_FOUND", err, "")
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (localEnd) canAppend() bool { return true }

func (l localEnd) notLink() error {
	if fi, err := os.Lstat(l.path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return linkRefused(l.path)
	}
	return nil
}

func linkRefused(where string) error {
	return out.Usage("%s is a symbolic link; --continue writes only to a plain file (copy it without --continue, or name the file the link points to)", where)
}

func (l localEnd) appendAt(_ context.Context, off, _ int64, r io.Reader) error {
	// again just before the write: the path may lead elsewhere by now
	if err := guardLocalWrite(l.cl, l.path); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE, l.perm)
	if err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "check that the folder exists and is writable", "%v", err)
	}
	if fi, err := f.Stat(); err != nil || fi.Size() != off {
		f.Close()
		return fileChanged(l.path, "changed while komando was copying")
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	_, err = io.Copy(f, r)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// A file on a server, over SFTP.

type serverEnd struct {
	cl     *call
	name   string       // the server, for messages
	c      *sshx.Client // nil: no shell to work out sums there
	sc     *sftp.Client
	path   string
	perm   os.FileMode // a new file's mode
	mkdirs bool        // create missing folders above a new file (-p)
}

func (s serverEnd) where() string {
	if s.name == "" {
		return s.path
	}
	return s.name + ":" + s.path
}

func (s serverEnd) size(context.Context) (int64, bool, error) {
	fi, err := s.sc.Stat(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return 0, false, nil
	case err != nil:
		return 0, false, fsErr(s.cl, s.path, err)
	case fi.IsDir():
		return 0, false, out.Usage("%s is a folder; --continue takes one file", s.where())
	}
	return fi.Size(), true, nil
}

func (s serverEnd) sumThere(ctx context.Context, n int64) (string, bool) {
	return remoteSum(ctx, s.c, s.path, n)
}

// remoteSum works out the sha256 of the first n bytes of p (n < 0: all)
// on the server with sha256sum or shasum. ok is false when it cannot: no
// such tool, or no shell (an SFTP-only account). A variable so tests can
// stand in for the server.
var remoteSum = func(ctx context.Context, c *sshx.Client, p string, n int64) (string, bool) {
	if c == nil || c.Host == nil || c.Host.Windows() {
		return "", false
	}
	r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: sumScript(p, n), Timeout: 6 * time.Hour, MaxOutput: 4096})
	if err != nil || r.ExitCode != 0 {
		return "", false
	}
	m := sumLine.FindStringSubmatch(r.Stdout)
	if m == nil {
		return "", false
	}
	return m[1], true
}

var sumLine = regexp.MustCompile(`^([0-9a-f]{64})\b`)

// sumScript is the shell line remoteSum runs: sha256sum (GNU, busybox)
// or shasum -a 256 (macOS, BSD), reading the file or its first n bytes.
func sumScript(p string, n int64) string {
	read := `cat -- "$f"`
	if n >= 0 {
		read = `head -c ` + strconv.FormatInt(n, 10) + ` -- "$f"`
	}
	return `f=` + sshx.Q(p) + `; [ -f "$f" ] && [ -r "$f" ] || exit 3; ` +
		`if command -v sha256sum >/dev/null 2>&1; then s="sha256sum"; ` +
		`elif command -v shasum >/dev/null 2>&1; then s="shasum -a 256"; else exit 4; fi; ` +
		read + ` | $s`
}

func (s serverEnd) openAt(_ context.Context, off int64) (io.ReadCloser, error) {
	f, err := s.sc.Open(s.path)
	if err != nil {
		return nil, fsErrHint(s.path, err, downloadPermHint)
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return nil, fsErr(s.cl, s.path, err)
	}
	return f, nil
}

func (serverEnd) canAppend() bool { return true }

func (s serverEnd) notLink() error {
	if fi, err := s.sc.Lstat(s.path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return linkRefused(s.where())
	}
	return nil
}

func (s serverEnd) appendAt(_ context.Context, off, _ int64, r io.Reader) error {
	if off == 0 {
		dir := path.Dir(s.path)
		if s.mkdirs {
			if err := s.sc.MkdirAll(dir); err != nil {
				return fsErr(s.cl, dir, err)
			}
		} else if _, err := s.sc.Stat(dir); errors.Is(err, os.ErrNotExist) {
			return folderMissing(dir)
		}
	}
	f, err := s.sc.OpenFile(s.path, os.O_WRONLY|os.O_CREATE)
	if err != nil {
		return fsErr(s.cl, s.path, err)
	}
	fi, err := f.Stat()
	if err != nil || fi.Size() != off {
		f.Close()
		return fileChanged(s.where(), "changed while komando was copying")
	}
	if off == 0 && s.perm != 0 {
		_ = f.Chmod(s.perm)
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return fsErr(s.cl, s.path, err)
	}
	_, err = io.Copy(f, r)
	if cerr := f.Close(); err == nil && cerr != nil {
		err = fsErr(s.cl, s.path, cerr)
	}
	return err
}

// An object in a storage conn.

type bucketEnd struct {
	conn string // for messages
	b    storex.Bucket
	key  string
}

func (e bucketEnd) where() string { return e.conn + ":" + e.key }

func (e bucketEnd) size(ctx context.Context) (int64, bool, error) {
	o, err := e.b.Stat(ctx, e.key)
	if err != nil {
		if toErr(err).Exit == out.ExitNotFound {
			return 0, false, nil
		}
		return 0, false, err
	}
	return o.Size, true, nil
}

func (bucketEnd) sumThere(context.Context, int64) (string, bool) { return "", false }

// openAt streams the object from off (getReader).
func (e bucketEnd) openAt(ctx context.Context, off int64) (io.ReadCloser, error) {
	return getReader(ctx, func(ctx context.Context, w io.Writer) error {
		_, err := storex.GetFrom(ctx, e.b, e.key, off, w)
		return err
	}), nil
}

func (e bucketEnd) canAppend() bool { return storex.CanAppend(e.b) }

// notLink: a storage conn shows no links (an SFTP conn's Append writes
// the path it names, as its uploads do).
func (bucketEnd) notLink() error { return nil }

func (e bucketEnd) appendAt(ctx context.Context, off, n int64, r io.Reader) error {
	if off == 0 && !e.canAppend() {
		return e.b.Put(ctx, e.key, r, n, mime.TypeByExtension(path.Ext(e.key)))
	}
	_, err := storex.Append(ctx, e.b, e.key, off, r)
	return err
}

// continueDownload is --continue for a file coming to this computer. An
// AI agent gets a text file of up to 16 MiB with its secret values shown
// as [hidden], and such a file cannot be continued. A larger one is
// checked for komando's vault values, as a whole download is: when one is
// in it, what this run added is taken off again, so the value does not
// stay on this computer.
func continueDownload(cl *call, ctx context.Context, src resumeEnd, dst string, perm os.FileMode, label string) (resumed, error) {
	if err := guardLocalWrite(cl, dst); err != nil {
		return resumed{}, err
	}
	mask := cl.out.Mask && !cl.revealOK()
	here := localEnd{cl: cl, path: dst, perm: localMode(perm)}
	before, existed, err := here.size(ctx)
	if err != nil {
		return resumed{}, err
	}
	if mask {
		n, ok, err := src.size(ctx)
		if err != nil {
			return resumed{}, err
		}
		if ok && n <= hiddenScanMax {
			return resumed{}, out.Errf(out.ExitUsage, "RESUME_UNSUPPORTED", "run it again without --continue: `komando download TARGET PATH`",
				"%s is saved for an AI agent with secret values shown as [hidden], which --continue cannot go on from; nothing was changed", src.where())
		}
	}
	r, err := resumeCopy(ctx, src, here, label)
	if !mask {
		return r, err
	}
	if after, _, _ := here.size(ctx); after == before {
		return r, err // nothing was added
	}
	found, serr := holdsVaultValue(cl, dst)
	if serr == nil && !found {
		return r, err
	}
	if existed {
		_ = os.Truncate(dst, before)
	} else {
		_ = os.Remove(dst)
	}
	if serr != nil {
		return resumed{}, serr
	}
	return resumed{}, out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
		revealHint(cl, "if the user wants the real file on this computer, re-run with --reveal"),
		"the file holds a value from komando's vault; komando does not copy it to this computer for an AI agent")
}

// holdsVaultValue says whether the file at p holds a value from komando's
// vault.
func holdsVaultValue(cl *call, p string) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := cl.out.NewValueScanner()
	if _, err := io.Copy(sc, f); err != nil {
		return false, err
	}
	return sc.Found(), nil
}

// continueUpload is --continue for one file going to a server.
func continueUpload(cl *call, ctx context.Context, c *sshx.Client, sc *sftp.Client, src, dst string, perm os.FileMode, o cpOpts) (xferStats, error) {
	if o.mode != "" {
		m, err := strconv.ParseUint(o.mode, 8, 32)
		if err != nil {
			return xferStats{}, out.Usage("--mode %q is not an octal mode like 0644", o.mode)
		}
		perm = os.FileMode(m)
	}
	there := serverEnd{cl: cl, name: hostName(c), c: c, sc: sc, path: dst, perm: perm, mkdirs: o.mkdirs}
	r, err := resumeCopy(ctx, localEnd{path: src}, there, src)
	if err != nil {
		return xferStats{}, err
	}
	if o.mode != "" {
		if err := sc.Chmod(dst, perm); err != nil {
			return xferStats{}, fsErr(cl, dst, err)
		}
	}
	return xferStats{Files: 1, Bytes: r.bytes, Dest: dst, SHA256: r.sum, ContinuedFrom: r.from}, nil
}

// hostName is the server c is connected to, or "" (tests run without one).
func hostName(c *sshx.Client) string {
	if c == nil || c.Host == nil {
		return ""
	}
	return c.Host.Name
}
