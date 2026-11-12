package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/storex"
)

// Downloads from servers: one file or a folder over SFTP, one file as root
// (--sudo), and how a file lands on this computer (fetchFile).

// downloadPermHint is what to do about a file the SSH user cannot read.
const downloadPermHint = "the SSH user cannot read it; for one file add --sudo, for a folder copy it to a readable place first with `komando exec --sudo`"

// download copies src from the server to dst on this computer. Files that
// already exist stay as they are unless overwrite is set, and every file is
// written to a temporary name first, so an interrupted download never
// leaves half a file behind.
func download(ctx context.Context, c *sshx.Client, sc *sftp.Client, src, dst string, o cpOpts) (xferStats, error) {
	lfi, lerr := os.Stat(dst)
	dstIsDir := lerr == nil && lfi.IsDir()
	dstSlash := strings.HasSuffix(dst, string(os.PathSeparator)) || strings.HasSuffix(dst, "/")
	if o.sudo {
		return sudoDownload(ctx, c, src, dst, dstIsDir || dstSlash, o.overwrite)
	}
	fi, err := sc.Stat(src)
	if err != nil {
		return xferStats{}, fsErrHint(src, err, downloadPermHint)
	}
	if !fi.IsDir() {
		if dstIsDir || dstSlash {
			dst = filepath.Join(dst, path.Base(src))
		}
		if err := guardSensitiveCopy(src); err != nil {
			return xferStats{}, err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return xferStats{}, err
		}
		in, err := sc.Open(src)
		if err != nil {
			return xferStats{}, fsErrHint(src, err, downloadPermHint)
		}
		defer in.Close()
		var watch io.Writer
		if p := transferProgress(o, path.Base(src), fi.Size()); p != nil {
			defer p.done()
			watch = p
		}
		n, sum, masked, err := fetchFile(ctx, in, dst, fi.Mode().Perm(), fi.ModTime(), o.overwrite, watch)
		if err != nil {
			return xferStats{}, err // nothing was saved: never "downloaded 1 file"
		}
		return xferStats{Files: 1, Bytes: n, Dest: dst, SHA256: sum, Masked: count(masked)}, nil
	}
	if !o.recursive {
		return xferStats{}, out.Usage("%s is a folder; add -r", src)
	}
	contents := strings.HasSuffix(src, "/")
	src = path.Clean(src)
	dst = filepath.FromSlash(treeDest(filepath.ToSlash(filepath.Clean(dst)), path.Base(src), contents, dstIsDir, dstSlash))
	st := xferStats{Dest: dst}
	w := sc.Walk(src)
	for w.Step() {
		if err := ctx.Err(); err != nil {
			return st, err // Ctrl-C: the files saved so far stay
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(w.Path(), src), "/")
		if w.Err() != nil {
			st.Errors = append(st.Errors, xferErr{Path: w.Path(), Message: toErr(fsErrHint(w.Path(), w.Err(), downloadPermHint)).Message})
			continue
		}
		if rel != "" && !filepath.IsLocal(filepath.FromSlash(rel)) {
			// names come from the server: never let one point outside dst
			return st, out.Errf(out.ExitRemote, "UNSAFE_PATH", "check the server for odd file names", "server sent the path %q, which leads outside %s; nothing outside the folder was written", w.Path(), dst)
		}
		lp := filepath.Join(dst, filepath.FromSlash(rel))
		if w.Stat().IsDir() {
			if err := os.MkdirAll(lp, 0o755); err != nil {
				return st, err
			}
			continue
		}
		if !w.Stat().Mode().IsRegular() {
			st.Skipped = append(st.Skipped, rel)
			continue
		}
		if guardSensitiveCopy(w.Path()) != nil {
			out.P.Skip(out.Skipped{Name: w.Path(), Kind: "file", Reason: "holds secrets; an AI agent needs --reveal, which the user allows, to copy it here"})
			continue
		}
		in, err := sc.Open(w.Path())
		if err != nil {
			st.Errors = append(st.Errors, xferErr{Path: w.Path(), Message: toErr(fsErrHint(w.Path(), err, downloadPermHint)).Message})
			continue
		}
		n, _, masked, err := fetchFile(ctx, in, lp, w.Stat().Mode().Perm(), w.Stat().ModTime(), o.overwrite, nil)
		in.Close()
		if ctx.Err() != nil {
			return st, ctx.Err()
		}
		if err != nil {
			e := toErr(err)
			if e.Code == "FILE_EXISTS" {
				return st, err // the same for every file: stop and say so
			}
			st.Errors = append(st.Errors, xferErr{Path: w.Path(), Message: e.Message})
			continue
		}
		st.Files++
		st.Bytes += n
		st.Masked += count(masked)
	}
	return st, nil
}

// sudoMaxBytes caps a --sudo download, which is read through memory.
const sudoMaxBytes = 512 << 20

// sudoDownload reads one file as root (sudo cat) and saves it here.
func sudoDownload(ctx context.Context, c *sshx.Client, src, dst string, intoDir, overwrite bool) (xferStats, error) {
	if err := guardSensitiveCopy(src); err != nil {
		return xferStats{}, err
	}
	r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: `if [ -d ` + sshx.Q(src) + ` ]; then echo "is a folder" >&2; exit 81; fi; cat -- ` + sshx.Q(src),
		Sudo: true, MaxOutput: sudoMaxBytes, Timeout: 30 * time.Minute})
	if err != nil {
		return xferStats{}, err
	}
	switch {
	case r.ExitCode == 81:
		return xferStats{}, out.Usage("--sudo downloads single files; %s is a folder", src)
	case r.ExitCode != 0 && strings.Contains(r.Stderr, "No such file"):
		return xferStats{}, fsErr(src, os.ErrNotExist)
	case r.ExitCode != 0:
		return xferStats{}, out.Errf(out.ExitRemote, "READ_FAILED", "check the path and its permissions with `komando fs stat TARGET PATH`, or add --sudo", "%s", strings.TrimSpace(r.Stderr))
	case r.StdoutTruncated:
		return xferStats{}, out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "copy it to a place the SSH user can read with `komando exec TARGET --sudo -- cp PATH /tmp/`, then download that",
			"%s is larger than %s, the most a --sudo download reads", src, humanBytes(sudoMaxBytes))
	}
	if intoDir {
		dst = filepath.Join(dst, path.Base(src))
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return xferStats{}, err
	}
	n, sum, masked, err := fetchFile(ctx, bytes.NewReader([]byte(r.Stdout)), dst, 0o644, time.Time{}, overwrite, nil)
	if err != nil {
		return xferStats{}, err
	}
	return xferStats{Files: 1, Bytes: n, Dest: dst, SHA256: sum, Masked: count(masked)}, nil
}

// fetchFile saves in as dst. For an AI agent a text file is saved the way
// fs cat shows it, secret values as [hidden] (masked; the sum is then left
// out: it would let a weak hidden value be guessed). The real file never
// reaches dst: the temporary file is masked before it is moved there.
// watch, when not nil, sees every byte (a progress line).
func fetchFile(ctx context.Context, in io.Reader, dst string, perm os.FileMode, mtime time.Time, overwrite bool, watch io.Writer) (n int64, sum string, masked bool, err error) {
	if _, err := os.Lstat(dst); err == nil && !overwrite {
		return 0, "", false, fileExists(dst)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".komando-download-*")
	if err != nil {
		return 0, "", false, err
	}
	defer os.Remove(tmp.Name()) // no-op once it has been moved into place
	h := sha256.New()
	// the destination watches ctx: an SFTP source keeps reading in parallel
	var w io.Writer = io.MultiWriter(tmp, h)
	if watch != nil {
		w = io.MultiWriter(tmp, h, watch)
	}
	n, err = io.Copy(storex.CtxWriter(ctx, w), in)
	if err == nil && out.P.Mask && !revealOK() {
		if masked, err = maskDownload(tmp, n); masked {
			n, _ = tmp.Seek(0, io.SeekEnd)
		}
	}
	if err == nil {
		err = tmp.Chmod(perm | 0o200)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, "", false, err
	}
	if !mtime.IsZero() {
		_ = os.Chtimes(tmp.Name(), mtime, mtime)
	}
	if overwrite {
		err = os.Rename(tmp.Name(), dst)
	} else {
		err = placeNew(tmp.Name(), dst)
	}
	if err != nil {
		return 0, "", false, err
	}
	if masked {
		return n, "", true, nil
	}
	return n, hex.EncodeToString(h.Sum(nil)), false, nil
}

// maskDownload rewrites f (n bytes) with the secret values hidden, if it is
// text komando can read whole (not binary, at most hiddenScanMax).
func maskDownload(f *os.File, n int64) (bool, error) {
	if n == 0 || n > hiddenScanMax {
		return false, nil
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, 0); err != nil {
		return false, err
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return false, nil
	}
	m := out.P.Redact(string(b))
	if m == string(b) {
		return false, nil
	}
	if err := f.Truncate(0); err != nil {
		return false, err
	}
	_, err := f.WriteAt([]byte(m), 0)
	return true, err
}

func count(b bool) int {
	if b {
		return 1
	}
	return 0
}

// placeNew moves tmp to dst only if dst does not exist yet. A hard link
// fails atomically when dst exists; file systems without hard links fall
// back to a check and a rename.
func placeNew(tmp, dst string) error {
	err := os.Link(tmp, dst)
	if err == nil {
		return nil
	}
	if os.IsExist(err) {
		return fileExists(dst)
	}
	if _, serr := os.Lstat(dst); serr == nil {
		return fileExists(dst)
	}
	return os.Rename(tmp, dst)
}

func fileExists(p string) error {
	return out.Errf(out.ExitConflict, "FILE_EXISTS", "choose another --to, remove the file, or pass --overwrite", "%s already exists on this computer", p)
}
