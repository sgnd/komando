package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// winCopy is runCp's work on one Windows server: one file each way.
// Folders (-r), --sudo and --mode have no Windows form yet.
func winCopy(ctx context.Context, c *sshx.Client, local, remote string, up bool, o cpOpts, many bool) (any, error) {
	switch {
	case o.recursive:
		return nil, notOnWindows("copying folders (-r)", []string{c.Host.Name})
	case o.sudo || o.mode != "":
		return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED", "Windows has no sudo or file modes: leave --sudo and --mode out, and log in as a user that may write there",
			"--sudo and --mode do not work on Windows servers")
	}
	if up {
		f, err := os.Open(local)
		if err != nil {
			return nil, localFileErr("PATH_NOT_FOUND", err, "")
		}
		defer f.Close()
		m, err := winWrite(ctx, c, remote, f, winWriteOpts{mkdirs: o.mkdirs, intoDir: filepath.Base(local)})
		if err != nil {
			return nil, err
		}
		return xferStats{Files: 1, Bytes: atoi64(m["bytes"]), Dest: m["path"], SHA256: m["sha256"], Replaced: m["replaced"] == "True"}, nil
	}
	dst := local
	if many {
		dst = filepath.Join(local, c.Host.Name) + string(os.PathSeparator)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return nil, err
		}
	}
	return winDownload(ctx, c, remote, dst, o.overwrite)
}

// winDownload saves the file src of a Windows server as dst (a folder:
// the file keeps its name in it).
func winDownload(ctx context.Context, c *sshx.Client, src, dst string, overwrite bool) (xferStats, error) {
	if err := guardSensitiveCopy(strings.ReplaceAll(src, `\`, "/")); err != nil {
		return xferStats{}, err
	}
	if fi, err := os.Stat(dst); (err == nil && fi.IsDir()) || strings.HasSuffix(dst, string(os.PathSeparator)) || strings.HasSuffix(dst, "/") {
		dst = filepath.Join(dst, winBase(src))
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return xferStats{}, err
	}
	script := winPath(src) + winCatch(`if (Test-Path -LiteralPath $p -PathType Container) { mark 'dir'; exit 0 }
if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { mark 'not-found'; exit 0 }
$fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
try {
  mark ('size=' + $fs.Length)
  $buf = New-Object byte[] 49152
  while (($k = $fs.Read($buf, 0, $buf.Length)) -gt 0) { [Console]::Out.WriteLine([Convert]::ToBase64String($buf, 0, $k)) }
  [Console]::Out.Flush()
} finally { $fs.Close() }`)
	w := &b64Sink{save: func(in io.Reader) (xferStats, error) {
		n, sum, masked, err := fetchFile(ctx, in, dst, 0o644, time.Time{}, overwrite, nil)
		if err != nil {
			return xferStats{}, err
		}
		return xferStats{Files: 1, Bytes: n, Dest: dst, SHA256: sum, Masked: count(masked)}, nil
	}}
	code, stderr, err := sshx.RunPS(ctx, c, script, nil, w)
	fail := err
	if e := winMarkerErr(src, w.marks); fail == nil && e != nil {
		fail = e
	}
	if fail == nil && (code != 0 || !w.started) {
		fail = out.Errf(out.ExitRemote, "READ_FAILED", "check the path with `komando fs stat "+c.Host.Name+" PATH`", "cannot read %s: %s", src, dash(strings.TrimSpace(stderr)))
	}
	res, serr := w.close(fail) // a failure never leaves a cut file behind
	if w.err != nil && w.err != fail {
		return xferStats{}, w.err // saving here failed first (the file exists, a full disk)
	}
	if fail != nil {
		return xferStats{}, fail
	}
	return res, serr
}

// b64Sink takes a download script's output: marker lines, then base64
// lines, which it decodes into save as they come (save runs once the size
// marker shows the file opened).
type b64Sink struct {
	save    func(io.Reader) (xferStats, error)
	marks   map[string]string
	partial []byte
	pw      *io.PipeWriter
	started bool
	wg      sync.WaitGroup
	res     xferStats
	err     error
	failed  error
}

func (s *b64Sink) Write(p []byte) (int, error) {
	s.partial = append(s.partial, p...)
	for {
		i := bytes.IndexByte(s.partial, '\n')
		if i < 0 {
			return len(p), nil
		}
		line := strings.TrimRight(string(s.partial[:i]), "\r")
		s.partial = s.partial[i+1:]
		if err := s.line(line); err != nil {
			s.failed = err
			return 0, err
		}
	}
}

func (s *b64Sink) line(l string) error {
	if kv, ok := strings.CutPrefix(l, "#komando:"); ok {
		if s.marks == nil {
			s.marks = map[string]string{}
		}
		k, v, _ := strings.Cut(kv, "=")
		s.marks[k] = v
		if k == "size" && !s.started {
			s.start()
		}
		return nil
	}
	if l == "" || !s.started {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(l)
	if err != nil {
		return err
	}
	_, err = s.pw.Write(b)
	return err
}

func (s *b64Sink) start() {
	pr, pw := io.Pipe()
	s.pw, s.started = pw, true
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.res, s.err = s.save(pr)
		pr.CloseWithError(s.err) // a failed save stops the writer
	}()
}

// close ends the data and waits for save. With fail (the transfer broke)
// save gets an error instead of the end of the file, so it keeps nothing.
func (s *b64Sink) close(fail error) (xferStats, error) {
	if !s.started {
		return xferStats{}, nil
	}
	if fail == nil {
		fail = s.failed
	}
	if fail != nil {
		s.pw.CloseWithError(fail)
	} else {
		s.pw.Close()
	}
	s.wg.Wait()
	if s.err == nil && s.failed != nil {
		return s.res, s.failed
	}
	return s.res, s.err
}

func atoi64(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }
