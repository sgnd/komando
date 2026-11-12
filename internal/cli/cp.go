package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/storex"
)

// splitRemote parses "TARGET:/path". Local paths (./x, /x, x) return ok=false.
// The colon that ends TARGET is the first one that is not part of a
// selector: the one after tag, label, kind or os (tag:edge:/srv), inside
// [an IPv6 address], or before a port (root@10.0.0.5:2222:/tmp).
func splitRemote(s string) (target, p string, ok bool) {
	i := remoteColon(s)
	if i <= 0 {
		return "", s, false
	}
	t := s[:i]
	if strings.ContainsAny(t, "/\\") || strings.HasPrefix(s, ".") {
		return "", s, false
	}
	return t, s[i+1:], true
}

// remoteColon is the index of the colon that ends TARGET, or -1.
func remoteColon(s string) int {
	word := 0 // where the current selector starts (after a comma)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ',':
			word = i + 1
		case '[':
			if j := strings.IndexByte(s[i:], ']'); j > 0 {
				i += j
			}
		case ':':
			switch strings.TrimPrefix(s[word:i], "!") {
			case "tag", "label", "kind", "os":
				continue
			}
			// a port only after an address (user@, [v6], an IP), so that
			// web1:12:30.log stays the file 12:30.log
			if n := digitsThenColon(s[i+1:]); n > 0 && adhocBefore(s[word:i]) {
				i += n
				continue
			}
			return i
		}
	}
	return -1
}

// adhocBefore says whether t, the text before a :PORT, is an address
// rather than a name from the inventory.
func adhocBefore(t string) bool {
	return strings.Contains(t, "@") || strings.HasSuffix(t, "]") || net.ParseIP(t) != nil
}

// digitsThenColon is the length of a port and its closing colon at the
// start of s ("2222:/tmp" gives 4), or 0.
func digitsThenColon(s string) int {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	if n == 0 || n > 5 || n >= len(s) || s[n] != ':' {
		return 0
	}
	return n
}

// splitArg is splitRemote that knows the inventory: "a:b.txt" is a local
// file when it exists here and "a" is no target komando knows.
func splitArg(s string) (target, p string, ok bool) {
	t, p, ok := splitRemote(s)
	if !ok {
		return t, p, ok
	}
	if _, err := os.Lstat(s); err == nil && !knownTarget(t) {
		return "", s, false
	}
	return t, p, ok
}

func knownTarget(t string) bool {
	st, err := loadState()
	if err != nil {
		return true
	}
	_, err = resolveSelection(st, t)
	return err == nil
}

// colonHint adds, to a target that was not found, that a local file name
// with a colon needs ./ in front.
func colonHint(err error, arg string) error {
	if err == nil {
		return nil
	}
	e := toErr(err)
	if !targetMissing[e.Code] || !strings.Contains(arg, ":") || strings.HasPrefix(arg, ".") {
		return err
	}
	hint := "if " + arg + " is a file on this computer, write it as ./" + arg
	if e.Hint != "" {
		hint += "; otherwise " + e.Hint
	}
	e.Hint = hint
	return e
}

// targetMissing are the codes for a target name komando does not know;
// a missing file or path is a different mistake and keeps its own hint.
var targetMissing = map[string]bool{
	"HOST_NOT_FOUND": true, "CONN_NOT_FOUND": true, "TARGET_NOT_FOUND": true,
	"GROUP_NOT_FOUND": true, "TARGET_EMPTY": true, "NO_MATCHING_TARGETS": true,
}

type xferErr struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

type xferStats struct {
	Host     string     `json:"host"`
	OK       bool       `json:"ok"`
	Files    int        `json:"files"`
	Bytes    int64      `json:"bytes"`
	Dest     string     `json:"dest"`
	SHA256   string     `json:"sha256,omitempty"`
	Replaced bool       `json:"replaced,omitempty"` // an upload replaced a file that was there
	Masked   int        `json:"masked,omitempty"`   // files saved with secret values shown as [hidden] (AI agents)
	Skipped  []string   `json:"skipped,omitempty"`  // symbolic links and other non-files, not copied
	Errors   []xferErr  `json:"errors,omitempty"`   // files that could not be copied (the rest were)
	Error    *out.Error `json:"error,omitempty"`
	up       bool
}

type xferData struct {
	Results []xferStats  `json:"results"`
	Summary fleetSummary `json:"summary"`
}

func (d xferData) Text() string {
	var b strings.Builder
	many := len(d.Results) > 1
	for _, r := range d.Results {
		pre := ""
		if many {
			pre = r.Host + ": "
		}
		if r.Error != nil && r.Files == 0 && len(r.Errors) == 0 {
			if many {
				fmt.Fprintf(&b, "%sFAILED [%s] %s\n", pre, r.Error.Code, r.Error.Message)
				if r.Error.Hint != "" {
					b.WriteString("  hint: " + r.Error.Hint + "\n")
				}
			}
			continue
		}
		verb := "downloaded"
		if r.up {
			verb = "uploaded"
		}
		files := "files"
		if r.Files == 1 {
			files = "file"
		}
		fmt.Fprintf(&b, "%s%s %d %s (%s) to %s", pre, verb, r.Files, files, humanBytes(r.Bytes), r.Dest)
		if r.Replaced {
			b.WriteString(", replacing the file there")
		}
		b.WriteString("\n")
		if r.Masked > 0 {
			fmt.Fprintf(&b, "%s%s saved with secret values shown as [hidden], as fs cat shows them\n", pre, countOf(r.Masked, "file"))
		}
		if len(r.Skipped) > 0 {
			fmt.Fprintf(&b, "%sskipped %s (symbolic links or special files): %s\n", pre, countOf(len(r.Skipped), "file"), shortList(r.Skipped, 5))
		}
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "%scould not copy %s: %s\n", pre, e.Path, e.Message)
		}
	}
	return b.String()
}

func shortList(l []string, n int) string {
	if len(l) <= n {
		return strings.Join(l, ", ")
	}
	return strings.Join(l[:n], ", ") + fmt.Sprintf(" and %d more", len(l)-n)
}

type cpOpts struct {
	recursive, sudo, mkdirs, overwrite bool
	mode                               string
	oneHost                            bool // one server: a big file shows progress at a terminal
}

// transferProgress is a progress line on stderr for one big file going to
// or from one server, at a person's terminal only: never for an AI agent,
// never on stdout, and nil (no line) otherwise.
func transferProgress(o cpOpts, name string, total int64) *progress {
	if !o.oneHost || total < progressMin || isAgent() || !term.IsTerminal(int(os.Stderr.Fd())) {
		return nil
	}
	return &progress{label: name, total: total}
}

// progressMin is the smallest file that shows progress: smaller ones are
// done before a line would be worth drawing.
const progressMin = 8 << 20

// bind adds the flags of both directions (cp); upload and download add
// only their own.
func (o *cpOpts) bind(c *cobra.Command) {
	o.bindUp(c, "upload: ")
	c.Flags().Lookup("sudo").Usage = "single files with sudo: install as root (upload), read as root (download)"
	c.Flags().BoolVar(&o.overwrite, "overwrite", false, "download: replace files that already exist on this computer")
}

func (o *cpOpts) bindUp(c *cobra.Command, prefix string) {
	c.Flags().BoolVarP(&o.recursive, "recursive", "r", false, "copy folders (a trailing / on SRC copies its contents)")
	c.Flags().BoolVarP(&o.sudo, "sudo", "s", false, prefix+"install into place with sudo (single files)")
	c.Flags().BoolVarP(&o.mkdirs, "parents", "p", false, prefix+"create missing parent folders")
	c.Flags().StringVar(&o.mode, "mode", "", prefix+"file mode, e.g. 0755")
}

const cpFolderRule = `Folders (-r), like cp and rsync:
  SRC/  (trailing slash)  the contents of SRC go into DST
  SRC   into a new DST    DST becomes the copy of SRC
  SRC   into a folder DST of the same name (site -> /var/www/site): DST is
        updated in place, so running the same copy again never nests site/site
  SRC   into another existing folder DST: the copy is DST/SRC
Symbolic links are not copied (they are listed as skipped). For repeatable
deploys that send only changed files, use ` + "`komando sync`.\n"

// uploadFolderRule is cpFolderRule in upload's words.
const uploadFolderRule = `Folders (-r), like cp and rsync:
  FILE/  (trailing slash)  the contents of FILE go into DEST
  FILE   into a new DEST    DEST becomes the copy of FILE
  FILE   into a folder DEST of the same name (site -> /var/www/site): DEST
         is updated in place, so running the same upload again never nests
         site/site
  FILE   into another existing folder DEST: the copy is DEST/FILE
Without DEST the folder keeps its name (servers: in the home folder). In
storage, a DEST ending in / is an existing folder. Symbolic links are not
copied (they are listed as skipped). For repeatable deploys that send only
changed files, use ` + "`komando sync`.\n"

// downloadFolderRule is cpFolderRule in download's words.
const downloadFolderRule = `Folders (-r), like cp and rsync:
  PATH/  (trailing slash)  the contents of PATH go into --to
  PATH   into a new --to    --to becomes the copy of PATH
  PATH   into a folder --to of the same name (/var/log/app -> ./app): it
         is updated in place, so downloading again never nests app/app
  PATH   into another existing folder --to: the copy is --to/NAME
Without --to it lands in the current folder under its own name. Symbolic
links are not copied (they are listed as skipped).
`

func cpCmd() *cobra.Command {
	var o cpOpts
	c := &cobra.Command{
		Use:   "cp SRC DST",
		Short: "Copy files, written SRC DST with TARGET:PATH (upload/download)",
		Long: `Remote paths are written TARGET:PATH (TARGET: alone, or TARGET:~/x, is the
login user's home folder). Uploads accept any target selector (@group,
tag:x, ...) and run in parallel. Downloads from several servers go to
DST/<server>/... . A single-file copy reports its sha256, so you can check it.
TARGET can be a storage conn too (backups:2026/db.sql.gz). cp is upload or
download written the cp way: the same code, flags and results.

` + cpFolderRule,
		Example: `  komando cp ./app.tar.gz @web:/tmp/app.tar.gz
  komando cp -r ./site web1:/var/www/site
  komando cp ./nginx.conf web1:/etc/nginx/nginx.conf --sudo
  komando cp web1:/var/log/nginx/error.log ./logs/
  komando cp @web:/etc/nginx/nginx.conf ./configs/
  komando cp ./db.sql.gz backups:2026/db.sql.gz`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcT, srcP, srcRemote := splitArg(args[0])
			dstT, dstP, dstRemote := splitArg(args[1])
			switch {
			case srcRemote && dstRemote:
				for _, a := range []struct{ t, arg string }{{srcT, args[0]}, {dstT, args[1]}} {
					if !knownTarget(a.t) {
						return out.Errf(out.ExitNotFound, "TARGET_NOT_FOUND", "if it is a file on this computer, write it as ./"+a.arg,
							"%q is not a server or conn komando knows", a.t)
					}
				}
				return out.Usage("komando cannot copy from one server straight to another: download, then upload")
			case !srcRemote && !dstRemote:
				return out.Usage("one side must be remote (TARGET:PATH); a local name with a colon is written ./name")
			case dstRemote:
				if o.overwrite {
					return out.Usage("--overwrite is for downloads; uploads always replace (the result says replaced)")
				}
				return colonHint(runUpload(cmd.Context(), cmd, dstT, srcP, dstP, false, o), args[1])
			}
			if o.mode != "" || o.mkdirs {
				return out.Usage("--mode and -p are for uploads")
			}
			return colonHint(runDownload(cmd.Context(), cmd, srcT, srcP, dstP, false, o), args[0])
		},
	}
	o.bind(c)
	return c
}

// runCp copies between this computer and the servers target picks, over
// SFTP: local to remote when up is true, else remote to local.
func runCp(ctx context.Context, name, target, remote, local string, up bool, o cpOpts) error {
	// checks that need no server come first
	if up {
		fi, err := os.Stat(local)
		if err != nil {
			return localFileErr("PATH_NOT_FOUND", err, "")
		}
		if fi.IsDir() && !o.recursive {
			return out.Usage("%s is a folder; add -r", local)
		}
		if fi.IsDir() && o.sudo {
			return out.Usage("--sudo uploads single files; upload the folder to a place you own (e.g. /tmp/%s), then `komando exec %s --sudo -- cp -r /tmp/%s/. DEST/`",
				filepath.Base(local), target, filepath.Base(local))
		}
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return err
	}
	src, dst := local, target+":"+remote
	if !up {
		src, dst = dst, src
	}
	if up {
		if err := guardLocalRead(local); err != nil {
			return err
		}
		if err := hiddenInLocal(local); err != nil {
			return err
		}
		if err := guard(st, hosts, "", true); err != nil {
			return err
		}
	} else if err := guardSensitiveCopy(remote); err != nil {
		return err // before connecting: a file named like a secret (a folder's files are checked one by one)
	}
	o.oneHost = len(hosts) == 1
	if g.dryRun {
		if err := downloadExists(local, remote, !up && !o.overwrite && !o.recursive && len(hosts) == 1); err != nil {
			return err // the real run would stop here
		}
		out.P.Print(name, map[string]any{"src": src, "dst": dst, "hosts": hostNames(hosts), "direction": map[bool]string{true: "upload", false: "download"}[up]}, nil)
		return nil
	}
	res := fanout(allowWindows(ctx), st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		if c.Host.Windows() {
			return winCopy(ctx, c, local, remote, up, o, len(hosts) > 1)
		}
		sc, err := sftpClient(c)
		if err != nil {
			return nil, err
		}
		defer sc.Close()
		rp := expandRemote(sc, remote)
		if up {
			return upload(ctx, c, sc, local, rp, o)
		}
		l := local
		if len(hosts) > 1 {
			l = filepath.Join(local, c.Host.Name) + string(os.PathSeparator)
			if err := os.MkdirAll(l, 0o755); err != nil {
				return nil, err
			}
		}
		return download(ctx, c, sc, rp, l, o)
	})
	data := xferData{Results: []xferStats{}}
	worst := 0
	var fails []hostFail
	for _, r := range res {
		s := xferStats{Host: r.Host.Name, up: up}
		if v, ok := r.Value.(xferStats); ok {
			s = v
			s.Host, s.up = r.Host.Name, up
		}
		if r.Err != nil {
			s.Error = toErr(r.Err)
		} else if len(s.Errors) > 0 {
			s.Error = out.Errf(out.ExitRemote, "PARTIAL_TRANSFER", "the other files were copied; fix the listed ones (permissions?) and run again",
				"%s could not be copied", countOf(len(s.Errors), "file"))
		}
		if s.Error != nil {
			worst = worse(worst, s.Error.Exit)
			fails = append(fails, hostFail{host: s.Host, reason: failReason(0, s.Error), err: s.Error})
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, s.Host)
		} else {
			s.OK = true
			data.Summary.OK++
		}
		data.Results = append(data.Results, s)
	}
	data.Summary.Total = len(res)
	audit(st, name, hostNames(hosts), "", data.Summary.Failed == 0, map[string]any{"src": src, "dst": dst})
	return finishFleet(name, data, runSummary{fleetSummary: data.Summary}, worst, fails)
}

// downloadExists is the FILE_EXISTS a single-file download of remote to
// local would meet, or nil. check is false when the download does not
// stop at an existing file (an upload, --overwrite, -r, several servers).
func downloadExists(local, remote string, check bool) error {
	fi, err := os.Stat(local)
	switch {
	case !check || err != nil:
		return nil
	case fi.IsDir():
		p := filepath.Join(local, path.Base(remote))
		if _, err := os.Lstat(p); err == nil {
			return fileExists(p)
		}
		return nil
	}
	return fileExists(local)
}

// treeDest is where a folder copy goes (see cpFolderRule). srcBase is the
// folder's own name, contents is a trailing slash on SRC, dstIsDir says
// DST exists as a folder.
func treeDest(dst, srcBase string, contents, dstIsDir, dstSlash bool) string {
	switch {
	case contents:
		return dst
	case dstSlash:
		return path.Join(dst, srcBase)
	case dstIsDir && path.Base(dst) != srcBase:
		return path.Join(dst, srcBase)
	}
	return dst
}

func upload(ctx context.Context, c *sshx.Client, sc *sftp.Client, src, dst string, o cpOpts) (xferStats, error) {
	fi, err := os.Stat(src)
	if err != nil {
		return xferStats{}, err
	}
	rfi, rerr := sc.Stat(dst)
	dstIsDir := rerr == nil && rfi.IsDir()
	if !fi.IsDir() {
		// "dst/" or existing remote dir => put inside it
		if strings.HasSuffix(dst, "/") || dstIsDir {
			dst = path.Join(dst, filepath.Base(src))
		}
		f, err := os.Open(src)
		if err != nil {
			return xferStats{}, err
		}
		defer f.Close()
		mode := o.mode
		if mode == "" {
			mode = "0" + strings.TrimPrefix(fileModeOctal(fi.Mode()), "0")
		}
		// streamed: a multi-GB backup never sits in memory
		var in io.Reader = storex.CtxReader(ctx, f)
		if p := transferProgress(o, filepath.Base(src), fi.Size()); p != nil {
			defer p.done()
			in = io.TeeReader(in, p)
		}
		r, err := writeRemoteFrom(ctx, c, sc, dst, in, writeOpts{sudo: o.sudo, mkdirs: o.mkdirs, mode: mode})
		if err != nil {
			return xferStats{}, err
		}
		if t, ok := r["followed"].(string); ok {
			dst = t
		}
		replaced, _ := r["replaced"].(bool)
		return xferStats{Files: 1, Bytes: r["bytes"].(int64), Dest: dst, SHA256: r["sha256"].(string), Replaced: replaced}, nil
	}
	contents := strings.HasSuffix(src, "/") || strings.HasSuffix(src, string(os.PathSeparator))
	dst = treeDest(strings.TrimSuffix(dst, "/"), filepath.Base(filepath.Clean(src)), contents, dstIsDir, strings.HasSuffix(dst, "/"))
	if !o.mkdirs {
		if _, err := sc.Stat(path.Dir(dst)); err != nil && os.IsNotExist(err) {
			return xferStats{}, folderMissing(path.Dir(dst))
		}
	}
	st := xferStats{Dest: dst}
	// a folder given as a symbolic link (./current -> releases/42) is copied
	// as the folder it names, as scp -r does; links inside it are skipped
	root := src
	if real, err := filepath.EvalSymlinks(src); err == nil {
		root = real
	}
	err = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr // Ctrl-C: stop here, the files sent so far stay
		}
		rel, _ := filepath.Rel(root, p)
		if err != nil {
			st.Errors = append(st.Errors, xferErr{Path: rel, Message: err.Error()})
			return nil
		}
		rp := path.Join(dst, filepath.ToSlash(rel))
		if info.IsDir() {
			if err := sc.MkdirAll(rp); err != nil {
				return fsErr(rp, err)
			}
			_ = sc.Chmod(rp, info.Mode().Perm())
			return nil
		}
		if !info.Mode().IsRegular() {
			st.Skipped = append(st.Skipped, filepath.ToSlash(rel))
			return nil
		}
		if skipLocalSecret(p) {
			return nil
		}
		n, err := putFile(ctx, sc, p, rp, info)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			st.Errors = append(st.Errors, xferErr{Path: filepath.ToSlash(rel), Message: toErr(err).Message})
			return nil
		}
		st.Files++
		st.Bytes += n
		return nil
	})
	return st, err
}

// putFile sends one file of a folder upload, keeping its mode and time. It
// is written as sync writes it, under a temporary name moved into place,
// so a broken or interrupted upload never leaves half a file behind.
func putFile(ctx context.Context, sc *sftp.Client, local, remote string, info os.FileInfo) (int64, error) {
	in, err := os.Open(local)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	err = sftpSide{sc: sc, root: path.Dir(remote)}.write(ctx, path.Base(remote), in, syncFile{Mode: info.Mode().Perm(), Mtime: info.ModTime()})
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func fileModeOctal(m os.FileMode) string {
	const digits = "01234567"
	p := uint32(m.Perm())
	return string([]byte{digits[(p>>6)&7], digits[(p>>3)&7], digits[p&7]})
}

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
			return st, out.Errf(out.ExitRemote, "UNSAFE_PATH", "nothing outside the folder was written; check the server for odd file names", "server sent the path %q, which leads outside %s", w.Path(), dst)
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
