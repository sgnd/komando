package storex

import (
	"context"
	"io"
	"os"
)

// A copy (io.Copy) does not watch a context: without these, Ctrl-C during a
// big transfer over SFTP, FTP or SMB was caught and ignored until the last
// byte had gone. CtxReader and CtxWriter end the copy at the next chunk
// once ctx is done, with ctx.Err(), so the caller's clean-up runs (the
// temporary file is removed) and the error says CANCELLED.

// CtxReader is r that stops reading once ctx is done. When r tells its size
// (a local file), the reader tells it too, so an SFTP upload still sends
// chunks in parallel.
func CtxReader(ctx context.Context, r io.Reader) io.Reader {
	cr := &ctxReader{ctx: ctx, r: r}
	if n := readerSize(r); n >= 0 {
		return &sizedCtxReader{ctxReader: cr, size: n}
	}
	return cr
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

type sizedCtxReader struct {
	*ctxReader
	size int64
}

// Size is what pkg/sftp's File.ReadFrom asks to pick parallel writes.
func (s *sizedCtxReader) Size() int64 { return s.size }

// readerSize is what is left to read from r, or -1 when r does not say.
func readerSize(r io.Reader) int64 {
	f, ok := r.(*os.File)
	if !ok {
		return -1
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return -1
	}
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil || pos > fi.Size() {
		return -1
	}
	return fi.Size() - pos
}

// CtxWriter is w that refuses to write once ctx is done. Wrap the
// destination, not the source, when the source is an SFTP file: its
// WriteTo reads chunks in parallel, which a wrapped source would hide.
func CtxWriter(ctx context.Context, w io.Writer) io.Writer {
	return &ctxWriter{ctx: ctx, w: w}
}

type ctxWriter struct {
	ctx context.Context
	w   io.Writer
}

func (c *ctxWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.w.Write(p)
}
