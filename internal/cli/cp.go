package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cli/kit/term"
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
func splitArg(cl *call, s string) (target, p string, ok bool) {
	t, p, ok := splitRemote(s)
	if !ok {
		return t, p, ok
	}
	if _, err := os.Lstat(s); err == nil && !knownTarget(cl, t) {
		return "", s, false
	}
	return t, p, ok
}

func knownTarget(cl *call, t string) bool {
	st, err := loadState()
	if err != nil {
		return true
	}
	_, err = resolveSelection(cl, st, t)
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
	"TARGET_NOT_FOUND": true, "GROUP_NOT_FOUND": true, "TARGET_EMPTY": true, "NO_MATCHING_TARGETS": true,
}

type xferErr struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

type xferStats struct {
	Host     string `json:"host"`
	OK       bool   `json:"ok"`
	Files    int    `json:"files"`
	Bytes    int64  `json:"bytes"`
	Dest     string `json:"dest"`
	SHA256   string `json:"sha256,omitempty"`
	Replaced bool   `json:"replaced,omitempty"` // an upload replaced a file that was there
	Masked   int    `json:"masked,omitempty"`   // files saved with secret values shown as [hidden] (AI agents)
	Kept     int    `json:"kept,omitempty"`     // a folder download: files already on this computer, left as they are
	// --continue: bytes that were already at the destination and stayed
	ContinuedFrom int64      `json:"continued_from_bytes,omitempty"`
	Source        string     `json:"source,omitempty"`  // a copy between two remote places: where it came from (TARGET:PATH)
	Skipped       []string   `json:"skipped,omitempty"` // symbolic links and other non-files, not copied
	Errors        []xferErr  `json:"errors,omitempty"`  // files that could not be copied (the rest were)
	Error         *out.Error `json:"error,omitempty"`
	verb          string     // uploaded, downloaded, copied
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
				fmt.Fprintf(&b, "%sfailed: %s (%s)\n", pre, r.Error.Message, r.Error.Code)
				if r.Error.Hint != "" {
					b.WriteString("  Hint: " + r.Error.Hint + "\n")
				}
			}
			continue
		}
		files := "files"
		if r.Files == 1 {
			files = "file"
		}
		fmt.Fprintf(&b, "%s%s %d %s (%s) to %s", pre, r.verb, r.Files, files, term.HumanBytes(r.Bytes), r.Dest)
		if r.ContinuedFrom > 0 {
			fmt.Fprintf(&b, ", going on after the %s already there", term.HumanBytes(r.ContinuedFrom))
		}
		if r.Replaced {
			b.WriteString(", replacing the file there")
		}
		b.WriteString("\n")
		if r.Masked > 0 {
			fmt.Fprintf(&b, "%s%s saved with secret values shown as [hidden], as fs cat shows them\n", pre, countOf(r.Masked, "file"))
		}
		if r.Kept > 0 {
			fmt.Fprintf(&b, "%skept %s already on this computer (--overwrite replaces them)\n", pre, countOf(r.Kept, "file"))
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
	oneHost                            bool  // one server: a big file shows progress at a terminal
	progress                           bool  // --progress: JSON lines on stderr with -o json
	resume                             bool  // --continue: go on with a file that was cut off
	size                               int64 // --size: the bytes an upload from stdin must send
	sized                              bool  // --size was given
}

// transferProgress is a progress line on stderr for one big file going to
// or from one server, at a person's terminal only: never for an AI agent,
// never on stdout, never beside --progress's JSON lines, and nil (no line)
// otherwise.
func transferProgress(cl *call, ctx context.Context, o cpOpts, name string, total int64) *progress {
	if !o.oneHost || total < progressMin || progressFrom(ctx) != nil || cl.isAgent() || !isTerminal(cl.out.Err) {
		return nil
	}
	return &progress{cl: cl, label: name, total: total}
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
	c.Flags().BoolVar(&o.progress, "progress", false, progressUsage)
	c.Flags().BoolVar(&o.resume, "continue", false, continueUsage)
	o.bindSize(c)
}

// bindSize adds --size, for an upload from stdin (-).
func (o *cpOpts) bindSize(c *cobra.Command) {
	c.Flags().Var(&bytesFlag{n: &o.size}, "size", "an upload from stdin (-): how many bytes it sends, like 10MiB; a stream of another length replaces nothing (SIZE_CONFLICT)")
}

func (o *cpOpts) bindUp(c *cobra.Command, prefix string) {
	c.Flags().BoolVarP(&o.recursive, "recursive", "r", false, "copy folders (a trailing / on SRC copies its contents)")
	c.Flags().BoolVarP(&o.sudo, "sudo", "s", false, prefix+"install into place with sudo (single files)")
	c.Flags().BoolVarP(&o.mkdirs, "parents", "p", false, prefix+"create missing parent folders")
	c.Flags().StringVar(&o.mode, "mode", "", prefix+"file mode, like 0755")
}

func cpCmd() *cobra.Command {
	var o cpOpts
	c := &cobra.Command{
		Use:  "cp SRC DST",
		Args: cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			ctx, finish := startProgress(cl, cmd.Context(), o.progress)
			return finish(runCpArgs(ctx, cmd, args, o))
		}),
	}
	o.bind(c)
	return c
}

// runCpArgs is cp: an upload or a download, by which side is TARGET:PATH.
func runCpArgs(ctx context.Context, cmd *cobra.Command, args []string, o cpOpts) error {
	cl := callOf(cmd)
	srcT, srcP, srcRemote := splitArg(cl, args[0])
	dstT, dstP, dstRemote := splitArg(cl, args[1])
	switch {
	case srcRemote && dstRemote:
		for _, a := range []struct{ t, arg string }{{srcT, args[0]}, {dstT, args[1]}} {
			if !knownTarget(cl, a.t) {
				return out.Errf(out.ExitNotFound, "TARGET_NOT_FOUND", "if it is a file on this computer, write it as ./"+a.arg,
					"%q is not a server or conn komando knows", a.t)
			}
		}
		return runRemoteCp(ctx, cmd, srcT, srcP, dstT, dstP, o)
	case !srcRemote && !dstRemote:
		return out.Usage("neither side is on a server: write one as TARGET:PATH (a local name with a colon is written ./name)")
	case dstRemote:
		if o.overwrite {
			return out.Usage("--overwrite is for downloads; uploads always replace (the result says replaced)")
		}
		return colonHint(runUpload(ctx, cmd, dstT, srcP, dstP, false, o), args[1])
	}
	if o.mode != "" || o.mkdirs {
		return out.Usage("--mode and -p are for uploads")
	}
	return colonHint(runDownload(ctx, cmd, srcT, srcP, dstP, false, o), args[0])
}

// runCp copies between this computer and the servers target picks, over
// SFTP: local to remote when up is true, else remote to local.
func runCp(cl *call, ctx context.Context, name, target, remote, local string, up bool, o cpOpts) error {
	// checks that need no server come first
	stdin := up && local == "-"
	if up && !stdin {
		fi, err := os.Stat(local)
		if err != nil {
			return localFileErr("PATH_NOT_FOUND", err, "")
		}
		if fi.IsDir() && !o.recursive {
			return out.Usage("%s is a folder; add -r", local)
		}
		if fi.IsDir() && o.sudo {
			return out.Usage("--sudo uploads single files; upload the folder to a place you own (for example /tmp/%s), then `komando exec %s --sudo -- cp -r /tmp/%s/. DEST/`",
				filepath.Base(local), target, filepath.Base(local))
		}
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(cl, st, target)
	if err != nil {
		return err
	}
	src, dst := local, target+":"+remote
	if !up {
		src, dst = dst, src
	}
	if stdin && len(hosts) != 1 {
		return out.Errf(out.ExitUsage, "USAGE", "name one server; to send the same file to many, save it to a file and upload that",
			"target %q matched %d servers; an upload from stdin (-) goes to one, as stdin is read once", target, len(hosts))
	}
	if up {
		if !stdin {
			if err := guardLocalRead(cl, local); err != nil {
				return err
			}
			if err := hiddenInLocal(local); err != nil {
				return err
			}
		}
		if err := guardUpload(cl, st, hosts, local); err != nil {
			return err
		}
	} else if err := guardDownload(cl, remote, local); err != nil {
		return err // before connecting: a file named like a secret (a folder's files are checked one by one)
	}
	o.oneHost = len(hosts) == 1
	if cl.dryRun() {
		if err := downloadExists(local, remote, !up && !o.overwrite && !o.recursive && !o.resume && len(hosts) == 1); err != nil {
			return err // the real run would stop here
		}
		cl.out.Print(name, map[string]any{"src": src, "dst": dst, "hosts": hostNames(hosts), "direction": map[bool]string{true: "upload", false: "download"}[up]}, nil)
		return nil
	}
	res := fanout(cl, allowWindows(ctx), st, hosts, cpProgress(cl, ctx, local, up, len(hosts), func(ctx context.Context, c *sshx.Client) (any, error) {
		if c.Host.Windows() && stdin {
			return nil, out.Usage("an upload from stdin (-) works with Linux and other Unix servers (SFTP); %s runs Windows", c.Host.Name)
		}
		if c.Host.Windows() && o.resume {
			return nil, out.Usage("--continue works with Linux and other Unix servers (SFTP); %s runs Windows", c.Host.Name)
		}
		if c.Host.Windows() {
			return winCopy(cl, ctx, c, local, remote, up, o, len(hosts) > 1)
		}
		sc, err := sftpClient(c)
		if err != nil {
			return nil, err
		}
		defer sc.Close()
		rp := expandRemote(sc, remote)
		if up {
			return upload(cl, ctx, c, sc, local, rp, o)
		}
		l := local
		if len(hosts) > 1 {
			l = filepath.Join(local, c.Host.Name) + string(os.PathSeparator)
			if err := os.MkdirAll(l, 0o755); err != nil {
				return nil, err
			}
		}
		return download(cl, ctx, c, sc, rp, l, o)
	}))
	verb := "downloaded"
	if up {
		verb = "uploaded"
	}
	var x xferTally
	for _, r := range res {
		s := xferStats{}
		if v, ok := r.Value.(xferStats); ok {
			s = v
		}
		s.Host, s.verb = r.Host.Name, verb
		x.add(s, r.Err)
	}
	data, worst, fails := x.data, x.worst, x.fails
	audit(cl, st, name, hostNames(hosts), "", data.Summary.Failed == 0, map[string]any{"src": src, "dst": dst})
	return finishFleet(cl, name, data, runSummary{fleetSummary: data.Summary}, worst, fails)
}

// xferTally adds up the results of a copy, one per server (or one for a
// copy between two remote places).
type xferTally struct {
	data  xferData
	worst int
	fails []hostFail
}

// add counts s, which ended with err (nil: it worked, unless files in it
// could not be copied).
func (x *xferTally) add(s xferStats, err error) {
	if x.data.Results == nil {
		x.data.Results = []xferStats{}
	}
	if err != nil {
		s.Error = toErr(err)
	} else if len(s.Errors) > 0 {
		s.Error = out.Errf(out.ExitRemote, "PARTIAL_TRANSFER", "fix the listed ones (permissions?) and run it again",
			"%s could not be copied; the other files were copied", countOf(len(s.Errors), "file"))
	}
	if s.Error != nil {
		x.worst = worse(x.worst, s.Error.Exit)
		x.fails = append(x.fails, hostFail{host: s.Host, reason: failReason(0, s.Error), err: s.Error})
		x.data.Summary.Failed++
		x.data.Summary.FailedHosts = append(x.data.Summary.FailedHosts, s.Host)
	} else {
		s.OK = true
		x.data.Summary.OK++
	}
	x.data.Summary.Total++
	x.data.Results = append(x.data.Results, s)
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

// treeDest is where a folder copy goes (see the folder rules in docs/features/files.md). srcBase is the
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

func upload(cl *call, ctx context.Context, c *sshx.Client, sc *sftp.Client, src, dst string, o cpOpts) (xferStats, error) {
	if src == "-" {
		return uploadStdin(cl, ctx, c, sc, dst, o)
	}
	fi, err := os.Stat(src)
	if err != nil {
		return xferStats{}, err
	}
	rfi, rerr := sc.Stat(dst)
	dstIsDir := rerr == nil && rfi.IsDir()
	if !fi.IsDir() {
		return uploadFile(cl, ctx, c, sc, src, dst, fi, dstIsDir, o)
	}
	return uploadTree(cl, ctx, sc, src, dst, dstIsDir, o)
}

// uploadFile sends one file, streamed and hashed as it goes.
func uploadFile(cl *call, ctx context.Context, c *sshx.Client, sc *sftp.Client, src, dst string, fi os.FileInfo, dstIsDir bool, o cpOpts) (xferStats, error) {
	// "dst/" or existing remote dir => put inside it
	if strings.HasSuffix(dst, "/") || dstIsDir {
		dst = path.Join(dst, filepath.Base(src))
	}
	if o.resume {
		return continueUpload(cl, ctx, c, sc, src, dst, fi.Mode().Perm(), o)
	}
	f, err := os.Open(src)
	if err != nil {
		return xferStats{}, err
	}
	defer f.Close()
	// a file already there keeps its mode (a 0600 .env stays 0600);
	// a new one gets the local file's, unless --mode says
	newMode := "0" + strings.TrimPrefix(fileModeOctal(fi.Mode()), "0")
	// streamed: a multi-GB backup never sits in memory
	pp := progressFrom(ctx)
	pp.start(src)
	var in io.Reader = storex.CtxReader(ctx, pp.reader(f))
	if p := transferProgress(cl, ctx, o, filepath.Base(src), fi.Size()); p != nil {
		defer p.done()
		in = io.TeeReader(in, p)
	}
	// C213: the bytes are hashed as they go; when an agent's window
	// approved a hash, other bytes stop before the file goes into place
	// fail closed: an agent's upload is sent only against the hash its
	// window showed for this same file (matched on the resolved file,
	// not on how the path was spelled)
	var want string
	agent := cl.caller().IsAgent()
	if agent {
		if cl.body == nil || cl.body.file == "" || cl.body.file != resolvedFile(src) {
			audit(cl, nil, "upload", nil, "", false, map[string]any{"file": src, "to": dst, "blocked": "FILE_CHANGED"})
			return xferStats{}, notShownFile(src)
		}
		want = cl.body.sha256()
	}
	r, err := writeRemoteFrom(cl, ctx, c, sc, dst, in, writeOpts{sudo: o.sudo, mkdirs: o.mkdirs, mode: o.mode, newMode: newMode, wantSHA256: want})
	if err != nil {
		if e := (*out.Error)(nil); errors.As(err, &e) && e.Code == "FILE_CHANGED" {
			audit(cl, nil, "upload", nil, "", false, map[string]any{"file": src, "to": dst, "blocked": "FILE_CHANGED"})
		}
		return xferStats{}, err
	}
	if !agent {
		// a person's upload: body_sha256 is the hash of what was sent
		sum, _ := hex.DecodeString(r["sha256"].(string))
		b := &approvalBody{label: "the file " + src, big: true, size: r["bytes"].(int64)}
		copy(b.sum[:], sum)
		setBody(cl, b)
	}
	pp.fileDone()
	if t, ok := r["followed"].(string); ok {
		dst = t
	}
	replaced, _ := r["replaced"].(bool)
	return xferStats{Files: 1, Bytes: r["bytes"].(int64), Dest: dst, SHA256: r["sha256"].(string), Replaced: replaced}, nil
}

// uploadTree sends a folder, file by file.
func uploadTree(cl *call, ctx context.Context, sc *sftp.Client, src, dst string, dstIsDir bool, o cpOpts) (xferStats, error) {
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
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
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
				return fsErr(cl, rp, err)
			}
			_ = sc.Chmod(rp, info.Mode().Perm())
			return nil
		}
		if !info.Mode().IsRegular() {
			st.Skipped = append(st.Skipped, filepath.ToSlash(rel))
			return nil
		}
		if skipLocalSecret(cl, p) {
			return nil
		}
		progressFrom(ctx).start(filepath.ToSlash(rel))
		n, err := putFile(cl, ctx, sc, p, rp, info)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			st.Errors = append(st.Errors, xferErr{Path: filepath.ToSlash(rel), Message: toErr(err).Message})
			return nil
		}
		progressFrom(ctx).fileDone()
		st.Files++
		st.Bytes += n
		return nil
	})
	return st, err
}

// putFile sends one file of a folder upload, keeping its time, and its mode
// unless a file is there already (that one keeps its own). It
// is written as sync writes it, under a temporary name moved into place,
// so a broken or interrupted upload never leaves half a file behind.
func putFile(cl *call, ctx context.Context, sc *sftp.Client, local, remote string, info os.FileInfo) (int64, error) {
	in, err := os.Open(local)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	mode := info.Mode().Perm()
	if fi, err := sc.Stat(remote); err == nil && fi.Mode().IsRegular() {
		mode = fi.Mode().Perm() // a file already there keeps its mode
	}
	err = sftpSide{cl: cl, sc: sc, root: path.Dir(remote)}.write(ctx, path.Base(remote), progressFrom(ctx).reader(in), syncFile{Mode: mode, Mtime: info.ModTime()})
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

// cpProgress sets --progress's totals for runCp and returns its work for
// one server: an upload knows the totals here; a download learns them from
// each server, so each server's work gets its own part.
func cpProgress(cl *call, ctx context.Context, local string, up bool, hosts int, fn func(context.Context, *sshx.Client) (any, error)) func(context.Context, *sshx.Client) (any, error) {
	pp := progressFrom(ctx)
	if up {
		files, bytes := localTotal(cl, local, pp != nil)
		pp.total(files*hosts, bytes*int64(hosts))
		return fn
	}
	pp.eachServer(hosts) // each server's file or folder has its own size
	return func(ctx context.Context, c *sshx.Client) (any, error) {
		ctx, settle := progressServer(ctx)
		defer settle()
		return fn(ctx, c)
	}
}

// localTotal is what an upload of local sends to one server: the file, or
// the regular files in the folder that upload sends (count false: 0, 0,
// without reading the folder).
func localTotal(cl *call, local string, count bool) (files int, bytes int64) {
	fi, err := os.Stat(local)
	if !count || err != nil {
		return 0, 0
	}
	if !fi.IsDir() {
		return 1, fi.Size()
	}
	root := local
	if real, err := filepath.EvalSymlinks(local); err == nil {
		root = real
	}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() && !skipLocalSecret(cl, p) {
			files++
			bytes += info.Size()
		}
		return nil
	})
	return files, bytes
}
