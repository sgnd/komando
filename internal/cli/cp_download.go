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
	"github.com/sgnd/komando/internal/tmpclean"
)

// Downloads from servers: one file or a folder over SFTP, one file as root
// (--sudo), and how a file lands on this computer (fetchFile).

// downloadPermHint is what to do about a file the SSH user cannot read.
const downloadPermHint = "the SSH user cannot read it; for one file add --sudo, for a folder copy it to a readable place first with `komando exec --sudo`"

// download copies src from the server to dst on this computer. Files that
// already exist stay as they are unless overwrite is set: one file stops
// with FILE_EXISTS, a folder keeps them (kept) and copies the rest. Every
// file is written to a temporary name first, so an interrupted download
// never leaves half a file behind.
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
	return downloadFolder(ctx, sc, src, dst, dstIsDir, dstSlash, o)
}

// downloadFolder is download -r: the folder src (its contents with a
// trailing /) into dst, as cpFolderRule says.
func downloadFolder(ctx context.Context, sc *sftp.Client, src, dst string, dstIsDir, dstSlash bool, o cpOpts) (xferStats, error) {
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
		if link := linkInDest(dst, filepath.FromSlash(rel), w.Stat().IsDir()); link != "" {
			return st, localLinkStop(rel, link)
		}
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
		if !o.overwrite {
			if lfi, err := os.Lstat(lp); err == nil {
				// already here: kept, and the rest still come (as storage -r does)
				keepLocal(&st, w.Path(), lp, lfi)
				continue
			}
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
			if lfi, lerr := os.Lstat(lp); lerr == nil && !o.overwrite && toErr(err).Code == "FILE_EXISTS" {
				keepLocal(&st, w.Path(), lp, lfi) // made here while it was copied
				continue
			}
			st.Errors = append(st.Errors, xferErr{Path: w.Path(), Message: toErr(err).Message})
			continue
		}
		st.Files++
		st.Bytes += n
		st.Masked += count(masked)
	}
	return st, nil
}

// linkInDest is the first symbolic link on the way from root to rel (the
// folders above a file, the folder itself), or "": writing through it
// would put the file wherever the link leads, outside the folder. The
// file's own name may be a link: a new file replaces the link itself.
func linkInDest(root, rel string, dir bool) string {
	if !dir {
		rel = filepath.Dir(rel)
	}
	return symlinkOn(root, rel)
}

func localLinkStop(rel, link string) error {
	return out.Errf(out.ExitConflict, "UNSAFE_PATH", "remove the link, or copy into a folder without links",
		"%s would be written through %s, a symbolic link on this computer that can lead outside the folder; nothing was written through it", rel, link)
}

// keepLocal counts a file of a folder download that is already on this
// computer and stays as it is. A folder where the file would go is listed
// as an error instead: the file is not here, and keeping it is not true.
func keepLocal(st *xferStats, remote, local string, fi os.FileInfo) {
	if fi.IsDir() {
		st.Errors = append(st.Errors, xferErr{Path: remote, Message: local + " is a folder on this computer"})
		return
	}
	st.Kept++
}

// sudoMaxBytes caps a --sudo download, which is read through memory.
const sudoMaxBytes = 512 << 20

// sudoDownload reads one file as root (sudo cat) and saves it here.
func sudoDownload(ctx context.Context, c *sshx.Client, src, dst string, intoDir, overwrite bool) (xferStats, error) {
	if err := guardSensitiveCopy(src); err != nil {
		return xferStats{}, err
	}
	r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: `if [ -d ` + sshx.Q(src) + ` ]; then echo "is a folder" >&2; exit 81; fi; ` + sudoReadScript(src, "cat"),
		Sudo: true, MaxOutput: sudoMaxBytes, Timeout: 30 * time.Minute})
	if err != nil {
		return xferStats{}, err
	}
	switch {
	case r.ExitCode == 81:
		return xferStats{}, out.Usage("--sudo downloads single files; %s is a folder", src)
	case r.ExitCode == sudoExitLink:
		return xferStats{}, readLinkStop(src)
	case r.ExitCode != 0 && strings.Contains(r.Stderr, "No such file"):
		return xferStats{}, fsErr(src, os.ErrNotExist)
	case r.ExitCode != 0:
		return xferStats{}, out.Errf(out.ExitRemote, "READ_FAILED", "check the path and its permissions with `komando fs stat SERVER PATH`, or add --sudo", "%s", strings.TrimSpace(r.Stderr))
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
	defer tmpclean.Add(tmp.Name())()
	h := sha256.New()
	// the destination watches ctx: an SFTP source keeps reading in parallel
	var w io.Writer = io.MultiWriter(tmp, h)
	if watch != nil {
		w = io.MultiWriter(tmp, h, watch)
	}
	if out.P.Mask && !revealOK() {
		n, masked, err = fetchMasked(ctx, in, tmp, h, watch)
	} else {
		n, err = io.Copy(storex.CtxWriter(ctx, w), in)
	}
	if err == nil {
		err = tmp.Chmod(localMode(perm))
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

// fetchMasked saves in to tmp for an AI agent. A text file komando can
// read whole is masked in memory, so its real secret values never reach
// the disk, not even for a moment in the temporary file. A binary or
// larger file cannot be masked; it is stopped when it holds a vault value.
func fetchMasked(ctx context.Context, in io.Reader, tmp *os.File, h io.Writer, watch io.Writer) (int64, bool, error) {
	seen := io.Writer(h)
	if watch != nil {
		seen = io.MultiWriter(h, watch)
	}
	var head bytes.Buffer
	n, err := io.Copy(storex.CtxWriter(ctx, io.MultiWriter(&head, seen)), io.LimitReader(in, hiddenScanMax+1))
	if err != nil {
		return 0, false, err
	}
	b := head.Bytes()
	if n <= hiddenScanMax && bytes.IndexByte(b, 0) < 0 {
		m := out.P.Redact(string(b))
		if _, err := tmp.WriteString(m); err != nil {
			return 0, false, err
		}
		return int64(len(m)), m != string(b), nil
	}
	sc := out.P.NewValueScanner()
	_, _ = sc.Write(b)
	if _, err := tmp.Write(b); err != nil {
		return 0, false, err
	}
	rest, err := io.Copy(storex.CtxWriter(ctx, io.MultiWriter(tmp, seen, sc)), in)
	if err == nil && sc.Found() {
		err = out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
			revealHint("it is binary or larger than komando reads whole, so its secrets cannot be shown as [hidden]; if the user wants the real file on this computer, re-run with --reveal"),
			"the file holds a value from komando's vault; komando does not copy it to this computer for an AI agent")
	}
	return n + rest, false, err
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

// localMode is the mode a file from a server gets on this computer: the
// server's, but never writable by others than you (a 0777 file is 0755
// here), and always readable and writable by you.
func localMode(perm os.FileMode) os.FileMode { return perm.Perm()&0o755 | 0o600 }
