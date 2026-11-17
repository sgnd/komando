package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"mime"
	"path"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// Streams (C72): `download TARGET PATH --to -` (and `cp TARGET:PATH -`)
// writes one file's bytes to stdout, and `upload TARGET - DEST` (and
// `cp - TARGET:PATH`) reads them from stdin. The phone apps read and
// write files this way, through ssh-gate.
//
// The contract for a stream to stdout: stdout carries the file's bytes as
// they are, and nothing else, whatever -o says. Everything komando says
// itself goes to stderr: with -o json one envelope at the end, the result
// ({host|conn, path|key, to: "stdout", bytes, sha256}) or the error. The
// exit code says which. A dry run streams nothing and answers on stdout,
// as every dry run does. When a stream breaks off, the bytes already on
// stdout stay there: the exit code is not 0 and the envelope says why.

// streamed is what went to stdout.
type streamed struct {
	bytes  int64
	sum    string // sha256 of what was written ("" when values were hidden)
	masked bool   // secret values were written as [hidden] (AI agents)
}

// streamData is the result of a stream to stdout, on stderr.
type streamData struct {
	Host   string `json:"host,omitempty"`
	Conn   string `json:"conn,omitempty"`
	Path   string `json:"path,omitempty"`
	Key    string `json:"key,omitempty"`
	To     string `json:"to"` // stdout
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256,omitempty"`
	Masked bool   `json:"masked,omitempty"` // secret values were written as [hidden]
}

// Text is empty: in text mode stdout has the file, and nothing is said
// when it worked.
func (streamData) Text() string { return "" }

// takeStdout takes stdout for a file's bytes: from here on, what komando
// prints itself (the result, an error) goes to stderr.
func takeStdout(cl *call) io.Writer {
	w := cl.out.W
	cl.out.W = cl.out.Stderr()
	return w
}

// streamsToStdout says whether cmd, as given, streams a file to stdout,
// so an error it ends with goes to stderr too (one found while its
// arguments were read).
func streamsToStdout(cl *call, cmd *cobra.Command) bool {
	if cl.flags.dryRun {
		return false
	}
	switch cmd.Name() {
	case "download":
		f := cmd.Flags().Lookup("to")
		return f != nil && f.Value.String() == "-"
	case "cp":
		a := cmd.Flags().Args()
		return len(a) == 2 && a[1] == "-"
	}
	return false
}

// streamTo writes what get writes to w. For an AI agent it keeps what a
// download to a file keeps, before a byte is written: a text file komando
// reads whole goes with its secret values as [hidden]; a binary one that
// holds what komando hides from agents is refused; a larger one is refused,
// as bytes on stdout cannot be taken back.
func streamTo(cl *call, ctx context.Context, w io.Writer, get func(io.Writer) (int64, error)) (streamed, error) {
	h := sha256.New()
	if !cl.out.Mask || cl.revealOK() {
		n, err := get(storex.CtxWriter(ctx, io.MultiWriter(w, h)))
		if err != nil {
			return streamed{bytes: n}, err
		}
		return streamed{bytes: n, sum: hex.EncodeToString(h.Sum(nil))}, nil
	}
	c := &agentStreamBuf{max: hiddenScanMax}
	if _, err := get(c); err != nil && !c.full {
		return streamed{}, err
	}
	if c.full {
		return streamed{}, out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "save it to a file with --to FILE",
			"the file is larger than %s, the most komando streams to an AI agent (it checks the whole file for secret values first)", humanBytes(hiddenScanMax))
	}
	b := c.buf.Bytes()
	text := string(b)
	if bytes.IndexByte(b, 0) >= 0 {
		// binary: refused when it holds anything komando hides from an
		// agent (a vault value, a secret by its shape, personal data where
		// the target hides it), as storage download does (agentStdout)
		if cl.out.BinaryHidden(b) {
			return streamed{}, out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
				revealHint(cl, "it is binary, so what it holds cannot be shown as [hidden]; if the user wants the real file, re-run with --reveal"),
				"the file holds a secret or personal data komando hides from AI agents, in binary form; komando does not stream it to an AI agent")
		}
	} else {
		text = cl.out.Redact(text)
	}
	if _, err := io.WriteString(w, text); err != nil {
		return streamed{}, err
	}
	r := streamed{bytes: int64(len(text)), masked: text != string(b)}
	if !r.masked {
		h.Write(b)
		r.sum = hex.EncodeToString(h.Sum(nil))
	}
	return r, nil
}

// agentStreamBuf keeps up to max bytes and then stops the copy into it.
type agentStreamBuf struct {
	buf  bytes.Buffer
	max  int
	full bool
}

func (c *agentStreamBuf) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		c.full = true
		return 0, io.ErrShortWrite
	}
	return c.buf.Write(p)
}

// serverReader reads the file p on a server over SFTP, for streamTo.
func serverReader(cl *call, ctx context.Context, sc *sftp.Client, p string) func(io.Writer) (int64, error) {
	return func(w io.Writer) (int64, error) {
		fi, err := sc.Stat(p)
		if err != nil {
			return 0, fsErrHint(p, err, downloadPermHint)
		}
		if fi.IsDir() {
			return 0, out.Usage("%s is a folder; --to - streams one file (save a folder with -r --to DIR)", p)
		}
		f, err := sc.Open(p)
		if err != nil {
			return 0, fsErrHint(p, err, downloadPermHint)
		}
		defer f.Close()
		n, err := io.Copy(w, storex.CtxReader(ctx, f))
		if err != nil {
			if ctx.Err() != nil {
				return n, ctx.Err()
			}
			return n, fsErr(cl, p, err)
		}
		return n, nil
	}
}

// streamServer is `download TARGET PATH --to -` from one server.
func streamServer(cl *call, ctx context.Context, name, target, p string, o cpOpts) error {
	switch {
	case o.recursive:
		return out.Usage("--to - streams one file; save a folder with -r --to DIR")
	case o.sudo:
		return out.Usage("--to - reads as the SSH user; read a root-only file with `komando fs cat %s %s --sudo`", target, p)
	}
	if err := guardSensitiveCopy(cl, p); err != nil {
		return err
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	h, err := oneServer(cl, st, target, "--to - streams one file from one server: name one")
	if err != nil {
		return err
	}
	from := h.Name + ":" + p
	if cl.flags.dryRun {
		cl.out.Print(name, map[string]any{"src": from, "dst": "stdout", "hosts": []string{h.Name}, "direction": "download"}, nil)
		return nil
	}
	raw := takeStdout(cl)
	if h.Windows() {
		return out.Usage("--to - works with Linux and other Unix servers (SFTP); %s runs Windows", h.Name)
	}
	if cl.flags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cl.flags.timeout)
		defer cancel()
	}
	r, err := streamFromServer(cl, ctx, st, h, p, raw)
	rec := map[string]any{"src": from, "dst": "stdout", "bytes": r.bytes}
	if err != nil {
		rec["error"] = toErr(err).Code
	}
	audit(cl, st, name, []string{h.Name}, "", err == nil, rec)
	if err != nil {
		return err
	}
	cl.out.Print(name, streamData{Host: h.Name, Path: p, To: "stdout", Bytes: r.bytes, SHA256: r.sum, Masked: r.masked}, nil)
	return nil
}

func streamFromServer(cl *call, ctx context.Context, st *store.State, h *store.Host, p string, w io.Writer) (streamed, error) {
	c, err := sshx.Dial(ctx, st, h, sshOpts(cl, st))
	if err != nil {
		return streamed{}, err
	}
	defer c.Close()
	sc, err := sftpClient(c)
	if err != nil {
		return streamed{}, err
	}
	defer sc.Close()
	return streamTo(cl, ctx, w, serverReader(cl, ctx, sc, expandRemote(sc, p)))
}

// stdinSource is stdin for an upload from it. It counts and hashes what
// it reads and, at the end, refuses (in place of io.EOF, so nothing is put
// into place) a stream of another length than --size, and a stream komando
// can read whole that holds a value komando hid ([hidden]): a masked copy
// would destroy the real value.
type stdinSource struct {
	r     io.Reader
	n     int64
	size  int64
	sized bool
	head  []byte
	h     hash.Hash
	ctx   context.Context
	err   error // the stream's own refusal, kept so a store's wrapping cannot hide it
}

func newStdinSource(cl *call, ctx context.Context, o cpOpts) *stdinSource {
	return &stdinSource{ctx: ctx, r: cl.stdin, size: o.size, sized: o.sized, h: sha256.New()}
}

func (s *stdinSource) Read(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.r.Read(p)
	s.n += int64(n)
	s.h.Write(p[:n])
	if room := hiddenScanMax + 1 - len(s.head); room > 0 {
		s.head = append(s.head, p[:min(n, room)]...)
	}
	switch {
	case s.ctx.Err() != nil:
		// Ctrl-C or a dropped link: stdin closing now (the program feeding
		// it got the same signal) is not the end of the file
		s.err = s.ctx.Err()
	case s.sized && s.n > s.size:
		s.err = sizeMismatch(s.size, "more")
	case err == io.EOF && s.sized && s.n != s.size:
		s.err = sizeMismatch(s.size, humanBytes(s.n)+" and stopped")
	case err == io.EOF && len(s.head) <= hiddenScanMax && out.HasHidden(string(s.head)):
		s.err = out.Errf(out.ExitUsage, "HIDDEN_VALUE",
			"edit the file on the server with `komando fs replace` (an --old with [hidden] in it matches the hidden value), and put a secret in with {{secret:NAME}}",
			"stdin holds a value komando hid ([hidden] or [secret:NAME]); uploading it would destroy the real value")
	}
	if s.err != nil {
		return n, s.err
	}
	return n, err
}

func (s *stdinSource) sum() string { return hex.EncodeToString(s.h.Sum(nil)) }

func sizeMismatch(want int64, got string) error {
	return out.Errf(out.ExitConflict, "SIZE_CONFLICT", "send the whole file again: `komando upload TARGET - DEST --size N`",
		"--size said %d bytes, and stdin sent %s; nothing was put into place", want, got)
}

// stdinDest refuses an upload from stdin that has no file name to go to.
func stdinDest(dest string) error {
	if dest == "" || dest[len(dest)-1] == '/' {
		return out.Usage("stdin has no file name: give DEST as the file's own path or key (not a folder)")
	}
	return nil
}

// storageUploadStdin is `storage upload CONN - KEY`: stdin streams into
// the object (a file server writes a temporary name first, an object
// store finishes the upload only at the end of the stream).
func storageUploadStdin(cl *call, ctx context.Context, name, conn, key string, o cpOpts) error {
	if err := storex.CheckKey(key); err != nil {
		return err
	}
	rec := map[string]any{"key": key, "file": "-"}
	if o.sized {
		rec["bytes"] = o.size
	}
	return withStoragePreview(cl, ctx, name, conn, driver.Verdict{Risk: driver.RiskWrite}, rec,
		func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
			replaced, err := s.Exists(ctx, key)
			if err != nil {
				return nil, err
			}
			// the length goes to the store as unknown even with --size, so it
			// reads stdin to its end and a stream that sends more is caught
			// (a store told the length would stop reading there and keep it)
			in := newStdinSource(cl, ctx, o)
			if err := s.Put(ctx, key, storex.CtxReader(ctx, in), -1, mime.TypeByExtension(path.Ext(key))); err != nil {
				if in.err != nil {
					return nil, in.err
				}
				return nil, err
			}
			rec["bytes"], rec["sha256"] = in.n, in.sum()
			return uploadData{Conn: c.Name, File: "-", Key: key, Bytes: in.n, Replaced: replaced, SHA256: in.sum()}, nil
		},
		func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
			replaced, err := s.Exists(ctx, key)
			return uploadData{Conn: c.Name, File: "-", Key: key, Bytes: max(o.size, 0), Replaced: replaced, DryRun: true}, err
		})
}

// uploadStdin is upload from stdin to one server: a temporary file, moved
// into place only when the whole stream arrived and checked out.
func uploadStdin(cl *call, ctx context.Context, c *sshx.Client, sc *sftp.Client, dst string, o cpOpts) (xferStats, error) {
	if fi, err := sc.Stat(dst); err == nil && fi.IsDir() {
		return xferStats{}, out.Usage("%s is a folder; stdin has no file name: give the file's own path", dst)
	}
	if err := stdinDest(dst); err != nil {
		return xferStats{}, err
	}
	in := newStdinSource(cl, ctx, o)
	r, err := writeRemoteFrom(cl, ctx, c, sc, dst, storex.CtxReader(ctx, in), writeOpts{sudo: o.sudo, mkdirs: o.mkdirs, mode: o.mode})
	if err != nil {
		if in.err != nil {
			return xferStats{}, in.err
		}
		return xferStats{}, err
	}
	if t, ok := r["followed"].(string); ok {
		dst = t
	}
	replaced, _ := r["replaced"].(bool)
	return xferStats{Files: 1, Bytes: in.n, Dest: dst, SHA256: in.sum(), Replaced: replaced}, nil
}
