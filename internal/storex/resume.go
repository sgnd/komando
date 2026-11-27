package storex

import (
	"context"
	"errors"
	"io"
	"os"
	"path"

	"github.com/minio/minio-go/v7"

	"github.com/sgnd/komando/internal/out"
)

// A copy that was cut off can go on where it stopped (--continue): it
// reads the source from an offset on, and adds the rest to the end of the
// destination. Every kind reads from an offset (GetFrom); only file
// servers can add to the end of a file (Append): object storage (S3, GCS,
// Azure Blob) stores whole objects.

// RangeGetter reads an object from an offset on without reading what is
// before it (an S3 ranged GET, an SFTP seek).
type RangeGetter interface {
	GetFrom(ctx context.Context, key string, off int64, w io.Writer) (int64, error)
}

// Appender adds r to the end of the file at key, which is off bytes long
// now (0: a new file). It refuses a file of another length.
type Appender interface {
	Append(ctx context.Context, key string, off int64, r io.Reader) (int64, error)
}

// Inner is the bucket inside a wrapper that has one (Unwrap), so the
// optional interfaces of the real bucket (Modes, Appender, RangeGetter)
// are found.
func Inner(b Bucket) Bucket {
	for {
		u, ok := b.(interface{ Unwrap() Bucket })
		if !ok {
			return b
		}
		b = u.Unwrap()
	}
}

// GetFrom writes the object at key from byte off on to w. A kind that
// cannot start in the middle reads from the start and drops the first off
// bytes, so it works with every kind, only with more to read.
func GetFrom(ctx context.Context, b Bucket, key string, off int64, w io.Writer) (int64, error) {
	if off == 0 {
		return b.Get(ctx, key, w)
	}
	if rg, ok := Inner(b).(RangeGetter); ok {
		return rg.GetFrom(ctx, key, off, w)
	}
	sw := &skipWriter{w: w, skip: off}
	n, err := b.Get(ctx, key, sw)
	return max(0, n-off), err
}

// CanAppend says whether b can add to the end of a file (Append).
func CanAppend(b Bucket) bool {
	_, ok := Inner(b).(Appender)
	return ok
}

// Append adds r to the end of the file at key (see Appender).
func Append(ctx context.Context, b Bucket, key string, off int64, r io.Reader) (int64, error) {
	a, ok := Inner(b).(Appender)
	if !ok {
		return 0, errors.ErrUnsupported
	}
	return a.Append(ctx, key, off, r)
}

// skipWriter drops the first skip bytes written to it.
type skipWriter struct {
	w    io.Writer
	skip int64
}

func (s *skipWriter) Write(p []byte) (int, error) {
	n := len(p)
	if s.skip >= int64(n) {
		s.skip -= int64(n)
		return n, nil
	}
	p = p[s.skip:]
	s.skip = 0
	if _, err := s.w.Write(p); err != nil {
		return 0, err
	}
	return n, nil
}

// GetFrom is an S3 ranged GET: bytes=off-.
func (s *s3Bucket) GetFrom(ctx context.Context, key string, off int64, w io.Writer) (int64, error) {
	full, err := s.Key(key)
	if err != nil {
		return 0, err
	}
	var o minio.GetObjectOptions
	if err := o.SetRange(off, 0); err != nil {
		return 0, out.Usage("%v", err)
	}
	obj, err := s.c.GetObject(ctx, s.bucket, full, o)
	if err != nil {
		return 0, toErr(err)
	}
	defer obj.Close()
	n, err := io.Copy(w, obj)
	return n, toErr(err)
}

// GetFrom reads the file from off on.
func (b *sftpBucket) GetFrom(ctx context.Context, key string, off int64, w io.Writer) (int64, error) {
	p, err := b.path(key)
	if err != nil {
		return 0, err
	}
	f, err := b.c.Open(p)
	if err != nil {
		return 0, sftpErr(err)
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return 0, sftpErr(err)
	}
	n, err := io.Copy(CtxWriter(ctx, w), f)
	return n, sftpErr(err)
}

// appendCheck is what every Append checks first: the file at key is a
// file off bytes long, or there is none and off is 0 (a new file).
func appendCheck(key string, o Object, found bool, off int64) error {
	switch {
	case found && o.Dir:
		return out.Usage("%q is a folder", key)
	case found && o.Size != off:
		return out.Errf(out.ExitConflict, "FILE_CHANGED", "run the same command again (`komando copy SOURCE DESTINATION --continue`): komando reads the file's length again",
			"%s changed while komando was copying (it is %d bytes, not %d); nothing was added", key, o.Size, off)
	case !found && off > 0:
		return out.Errf(out.ExitConflict, "FILE_CHANGED", "run the same command again (`komando copy SOURCE DESTINATION --continue`): komando reads the file's length again",
			"%s was removed while komando was copying; nothing was added", key)
	}
	return nil
}

// Append writes r at the end of the file, which must be off bytes long
// (a new file when off is 0; its folders are made, its mode is 0644).
func (b *sftpBucket) Append(ctx context.Context, key string, off int64, r io.Reader) (int64, error) {
	p, err := b.path(key)
	if err != nil {
		return 0, err
	}
	o, found, err := b.Lookup(ctx, key)
	if err != nil {
		return 0, err
	}
	if err := appendCheck(key, o, found, off); err != nil {
		return 0, err
	}
	if !found {
		if err := b.c.MkdirAll(path.Dir(p)); err != nil {
			return 0, sftpErr(err)
		}
	}
	f, err := b.c.OpenFile(p, os.O_WRONLY|os.O_CREATE)
	if err != nil {
		return 0, sftpErr(err)
	}
	if off == 0 {
		_ = f.Chmod(0o644)
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return 0, sftpErr(err)
	}
	n, err := io.Copy(f, CtxReader(ctx, r))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, sftpErr(err)
}

// Append adds r to the end of the file with APPE, after checking that the
// file is off bytes long (a new file when off is 0; its folders are made).
func (b *ftpBucket) Append(ctx context.Context, key string, off int64, r io.Reader) (int64, error) {
	p, err := b.path(key)
	if err != nil {
		return 0, err
	}
	o, found, err := b.Lookup(ctx, key)
	if err != nil {
		return 0, err
	}
	if err := appendCheck(key, o, found, off); err != nil {
		return 0, err
	}
	if !found {
		if dir := path.Dir(p); dir != "/" {
			_ = b.mkdirs(dir) // a folder that cannot be made fails the APPE
		}
	}
	cr := &countReader{r: CtxReader(ctx, r)}
	if err := b.c.Append(p, cr); err != nil {
		return cr.n, ftpStepErr("APPE", err)
	}
	return cr.n, nil
}

// Append writes r at the end of the file on the share, after checking
// that it is off bytes long (a new file when off is 0; its folders are
// made).
func (b *smbBucket) Append(ctx context.Context, key string, off int64, r io.Reader) (int64, error) {
	p, err := b.path(key)
	if err != nil {
		return 0, err
	}
	o, found, err := b.Lookup(ctx, key)
	if err != nil {
		return 0, err
	}
	if err := appendCheck(key, o, found, off); err != nil {
		return 0, err
	}
	share := b.fs(ctx)
	if !found {
		if dir := path.Dir(p); dir != "." {
			if err := share.MkdirAll(dir); err != nil {
				return 0, smbErr(err)
			}
		}
	}
	f, err := share.OpenEnd(p)
	if err != nil {
		return 0, smbErr(err)
	}
	n, err := io.Copy(f, CtxReader(ctx, r))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, smbErr(err)
}

// countReader counts the bytes read through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
