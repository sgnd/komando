package cli

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// cp with TARGET:PATH on both sides copies between two remote places:
// server to server, storage to storage, or one of each. The bytes go from
// the source's reader straight into the destination's writer (an io.Pipe
// where the source is storage), through this computer's memory, and are
// never written to its disk. One audit record covers the whole copy.

// copyEnd is one side of such a copy: one server or one storage conn.
type copyEnd struct {
	host *store.Host // a server, or
	conn *store.Conn // a storage conn
	c    *sshx.Client
	sc   *sftp.Client
	b    storex.Bucket
}

func (e *copyEnd) name() string {
	if e.host != nil {
		return e.host.Name
	}
	return e.conn.Name
}

func (e *copyEnd) server() bool { return e.host != nil }

// resolveCopyEnd finds the one server or storage conn target names.
func resolveCopyEnd(cl *call, st *store.State, target string) (*copyEnd, error) {
	storage, err := fileTarget(cl, target)
	if err != nil {
		return nil, err
	}
	if storage {
		c, err := singleConn(cl, st, target, "storage")
		if err != nil {
			return nil, err
		}
		return &copyEnd{conn: c}, nil
	}
	h, err := oneServer(cl, st, target, "a copy between two remote places goes from one server or conn to one: name one on each side, for example `komando copy web1:/tmp/a web2:/tmp/a`")
	if err != nil {
		return nil, err
	}
	return &copyEnd{host: h}, nil
}

// open connects to the server or the conn.
func (e *copyEnd) open(cl *call, ctx context.Context, st *store.State) error {
	if e.conn != nil {
		b, err := openBucket(cl, ctx, st, e.conn)
		if err != nil {
			return namedHint(err, e.conn.Name)
		}
		e.b = b
		return nil
	}
	if err := refuseWindows(ctx, e.host); err != nil {
		return err
	}
	c, err := sshx.Dial(ctx, st, e.host, sshOpts(cl, st))
	if err != nil {
		return err
	}
	sc, err := sftpClient(c)
	if err != nil {
		c.Close()
		return err
	}
	e.c, e.sc = c, sc
	return nil
}

func (e *copyEnd) close() {
	if e.b != nil {
		e.b.Close()
	}
	if e.sc != nil {
		e.sc.Close()
	}
	if e.c != nil {
		e.c.Close()
	}
}

// path is p as this side reads it: ~ and an empty path are the login
// user's home folder on a server; a key in a conn is as given.
func (e *copyEnd) path(p string) string {
	if e.server() {
		return expandRemote(e.sc, p)
	}
	return strings.TrimPrefix(p, "/")
}

// side is the folder (server) or prefix (conn) root as a sync side, which
// lists, reads and writes the files in it.
func (e *copyEnd) side(cl *call, root string) syncSide {
	if e.server() {
		return sftpSide{cl: cl, sc: e.sc, root: root}
	}
	return bucketSide{b: e.b, prefix: folderKey(root)}
}

// resumeEnd is one file of this side, for --continue.
func (e *copyEnd) resumeEnd(cl *call, p string, perm os.FileMode, mkdirs bool) resumeDst {
	if e.server() {
		return serverEnd{cl: cl, name: e.host.Name, c: e.c, sc: e.sc, path: p, perm: perm, mkdirs: mkdirs}
	}
	return bucketEnd{conn: e.conn.Name, b: e.b, key: p}
}

// copyStat is what a copy needs to know about its source.
type copyStat struct {
	size  int64
	dir   bool
	mode  os.FileMode // 0: storage keeps no mode
	mtime time.Time
}

// stat looks at p on this side; exists is false when there is nothing.
// In a conn, a key with objects under key/ is a folder.
func (e *copyEnd) stat(ctx context.Context, p string) (copyStat, bool, error) {
	if e.server() {
		fi, err := e.sc.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			return copyStat{}, false, nil
		}
		if err != nil {
			return copyStat{}, false, fsErrHint(p, err, downloadPermHint)
		}
		return copyStat{size: fi.Size(), dir: fi.IsDir(), mode: fi.Mode().Perm(), mtime: fi.ModTime()}, true, nil
	}
	if p != "" && !strings.HasSuffix(p, "/") {
		// Lookup, not Stat: a file server's Stat answers a folder with a
		// usage error
		o, found, err := e.b.Lookup(ctx, p)
		if err != nil {
			return copyStat{}, false, err
		}
		if found && !o.Dir {
			return copyStat{size: o.Size, mtime: o.Modified}, true, nil
		}
	}
	objs, _, err := e.b.List(ctx, folderKey(p), true, 1)
	if err != nil {
		if toErr(err).Exit == out.ExitNotFound {
			return copyStat{}, false, nil
		}
		return copyStat{}, false, err
	}
	return copyStat{dir: true}, len(objs) > 0, nil
}

// runRemoteCp is cp with TARGET:PATH on both sides.
func runRemoteCp(ctx context.Context, cmd *cobra.Command, srcT, srcP, dstT, dstP string, o cpOpts) error {
	cl := callOf(cmd)
	name := cmdName(cmd)
	if err := continueFlags(o); err != nil {
		return err
	}
	switch {
	case o.sudo:
		return out.Usage("--sudo copies to or from this computer; between two remote places komando reads and writes as the SSH user")
	case o.overwrite:
		return out.Usage("--overwrite is for downloads; a copy between two remote places always replaces the file there (the result says replaced)")
	case o.sized:
		return out.Usage("--size is for an upload from stdin (-)")
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	src, err := resolveCopyEnd(cl, st, srcT)
	if err != nil {
		return err
	}
	dst, err := resolveCopyEnd(cl, st, dstT)
	if err != nil {
		return err
	}
	// what is copied is data from src: personal data hidden there stays
	// hidden from an AI agent (agentScan), as for a download from src
	if src.server() {
		notePersonal(cl, st, []*store.Host{src.host}, nil)
	} else {
		notePersonal(cl, st, nil, []*store.Conn{src.conn})
	}
	if !dst.server() && (o.mkdirs || o.mode != "") {
		return out.Usage("-p and --mode are for servers")
	}
	if _, err := strconv.ParseUint(o.mode, 8, 32); o.mode != "" && err != nil {
		return out.Usage("--mode %q is not an octal mode like 0644", o.mode)
	}
	if err := guardSensitiveRemote(cl, srcP); err != nil {
		return err
	}
	var hosts, conns []string
	for _, e := range []*copyEnd{src, dst} {
		if e.server() {
			hosts = append(hosts, e.name())
		} else {
			conns = append(conns, e.name())
		}
	}
	// a protected destination asks once, as an upload to it asks
	if dst.server() {
		err = Guard(cl, st, []*store.Host{dst.host}, "", true)
	} else {
		err = GuardConns(cl, st, []*store.Conn{dst.conn}, driver.Verdict{Risk: driver.RiskWrite})
	}
	if err != nil {
		return err
	}
	from, to := src.name()+":"+srcP, dst.name()+":"+dstP
	if cl.dryRun() {
		plan := map[string]any{"src": from, "dst": to, "direction": "copy"}
		if hosts != nil {
			plan["hosts"] = hosts
		}
		if conns != nil {
			plan["conns"] = conns
		}
		cl.out.Print(name, plan, nil)
		return nil
	}
	if cl.flags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cl.flags.timeout)
		defer cancel()
	}
	rec := map[string]any{"src": from, "dst": to}
	if conns != nil {
		rec["conns"] = conns
	}
	s, err := connectAndCopy(cl, ctx, st, src, dst, srcP, dstP, o)
	s.Host, s.verb = dst.name(), "copied"
	s.Source, s.Dest = cmp.Or(s.Source, from), cmp.Or(s.Dest, to)
	var x xferTally
	x.add(s, err)
	r := x.data.Results[0]
	rec["files"], rec["bytes"] = r.Files, r.Bytes
	if r.SHA256 != "" {
		rec["sha256"] = r.SHA256
	}
	if r.Error != nil {
		rec["error"] = r.Error.Code
	}
	audit(cl, st, name, hosts, "", r.Error == nil, rec)
	return finishFleet(cl, name, x.data, runSummary{fleetSummary: x.data.Summary}, x.worst, x.fails)
}

// connectAndCopy connects to both sides and copies.
func connectAndCopy(cl *call, ctx context.Context, st *store.State, src, dst *copyEnd, srcP, dstP string, o cpOpts) (xferStats, error) {
	if err := src.open(cl, ctx, st); err != nil {
		return xferStats{}, err
	}
	defer src.close()
	if err := dst.open(cl, ctx, st); err != nil {
		return xferStats{}, err
	}
	defer dst.close()
	return remoteCopy(cl, ctx, src, dst, srcP, dstP, o)
}

// remoteCopy copies srcP on src to dstP on dst, both connected: one file,
// or a folder with -r (as the folder rules in docs/features/files.md say).
func remoteCopy(cl *call, ctx context.Context, src, dst *copyEnd, srcP, dstP string, o cpOpts) (xferStats, error) {
	contents := strings.HasSuffix(srcP, "/")
	dstSlash := strings.HasSuffix(dstP, "/") || dstP == ""
	sp, dp := src.path(srcP), dst.path(dstP)
	si, ok, err := src.stat(ctx, sp)
	if err != nil {
		return xferStats{}, err
	}
	if !ok {
		return xferStats{}, out.Errf(out.ExitNotFound, "PATH_NOT_FOUND", "check the source path", "%s:%s does not exist; nothing was changed", src.name(), srcP)
	}
	dstIsDir := false
	if dst.server() {
		if fi, err := dst.sc.Stat(dp); err == nil && fi.IsDir() {
			dstIsDir = true
		}
	}
	if si.dir {
		if !o.recursive {
			return xferStats{}, out.Errf(out.ExitUsage, "IS_A_DIRECTORY",
				fmt.Sprintf("copy the folder and everything in it with -r: `komando copy -r %s %s`", argQ(src.name()+":"+srcP), argQ(dst.name()+":"+dstP)),
				"%s:%s is a folder, not a file", src.name(), srcP)
		}
		return copyFolder(cl, ctx, src, dst, strings.TrimSuffix(sp, "/"), dp, contents, dstIsDir, dstSlash, o)
	}
	if dstIsDir || dstSlash {
		dp = path.Join(dp, path.Base(sp))
	}
	if o.resume {
		// --continue adds to the file in place: an AI agent's source is
		// read first, so a vault value is found before anything is added
		if agentScans(cl) {
			r, err := src.side(cl, path.Dir(sp)).open(ctx, path.Base(sp))
			if err != nil {
				return xferStats{}, err
			}
			_, err = io.Copy(io.Discard, storex.CtxReader(ctx, agentScan(cl, r, src.name()+":"+sp)))
			r.Close()
			if err != nil {
				return xferStats{}, err
			}
		}
		var from resumeEnd = src.resumeEnd(cl, sp, 0, false)
		if agentScans(cl) {
			from = scannedEnd{resumeEnd: from, cl: cl} // what is added, as it is read
		}
		r, err := resumeCopy(ctx, from, dst.resumeEnd(cl, dp, copyMode(si.mode, o), o.mkdirs), sp)
		if err != nil {
			return xferStats{}, err
		}
		return xferStats{Files: 1, Bytes: r.bytes, Dest: dst.name() + ":" + dp, Source: src.name() + ":" + sp, SHA256: r.sum, ContinuedFrom: r.from}, nil
	}
	return copyOne(cl, ctx, src, dst, sp, dp, si, o)
}

// copyMode is the mode a new file gets on a server: --mode, else the
// source's, else 0644.
func copyMode(src os.FileMode, o cpOpts) os.FileMode {
	if o.mode != "" {
		if m, err := strconv.ParseUint(o.mode, 8, 32); err == nil {
			return os.FileMode(m)
		}
	}
	if src == 0 {
		return 0o644
	}
	return src
}

// copyOne streams one file from src to dst and returns its sha256.
func copyOne(cl *call, ctx context.Context, src, dst *copyEnd, sp, dp string, si copyStat, o cpOpts) (xferStats, error) {
	r, err := src.side(cl, path.Dir(sp)).open(ctx, path.Base(sp))
	if err != nil {
		return xferStats{}, err
	}
	defer r.Close()
	pp := progressFrom(ctx)
	pp.total(1, si.size)
	pp.start(sp)
	h := sha256.New()
	in := storex.CtxReader(ctx, io.TeeReader(pp.reader(agentScan(cl, r, src.name()+":"+sp)), h))
	st := xferStats{Files: 1, Source: src.name() + ":" + sp}
	if dst.server() {
		newMode := ""
		if si.mode != 0 {
			newMode = "0" + fileModeOctal(si.mode)
		}
		res, err := writeRemoteFrom(cl, ctx, dst.c, dst.sc, dp, in, writeOpts{mkdirs: o.mkdirs, mode: o.mode, newMode: newMode})
		if err != nil {
			return xferStats{}, err
		}
		if t, ok := res["followed"].(string); ok {
			dp = t
		}
		st.Bytes, st.SHA256 = res["bytes"].(int64), res["sha256"].(string)
		st.Replaced, _ = res["replaced"].(bool)
	} else {
		replaced, err := dst.b.Exists(ctx, dp)
		if err != nil {
			return xferStats{}, err
		}
		cr := &countingReader{r: in}
		if err := dst.b.Put(ctx, dp, cr, si.size, mime.TypeByExtension(path.Ext(dp))); err != nil {
			return xferStats{}, err
		}
		st.Bytes, st.SHA256, st.Replaced = cr.n, hex.EncodeToString(h.Sum(nil)), replaced
	}
	if ctx.Err() != nil {
		return xferStats{}, ctx.Err()
	}
	pp.fileDone()
	st.Dest = dst.name() + ":" + dp
	return st, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// copyFolder copies the folder sp on src into dst, file by file; a file
// that cannot be copied is listed and the rest still go.
func copyFolder(cl *call, ctx context.Context, src, dst *copyEnd, sp, dp string, contents, dstIsDir, dstSlash bool, o cpOpts) (xferStats, error) {
	base := path.Base(sp)
	if sp == "" || sp == "." {
		base = ""
	}
	root := treeDest(strings.TrimSuffix(dp, "/"), base, contents, dstIsDir, dstSlash && dp != "")
	if !dst.server() && dp == "" && !contents {
		root = base // a conn's root, like upload CONN DIR -r
	}
	if dst.server() && !o.mkdirs {
		if _, err := dst.sc.Stat(path.Dir(root)); errors.Is(err, os.ErrNotExist) {
			return xferStats{}, folderMissing(path.Dir(root))
		}
	}
	files, err := src.side(cl, sp).list(ctx)
	if errors.Is(err, errSideMissing) {
		return xferStats{}, out.Errf(out.ExitNotFound, "PATH_NOT_FOUND", "check the source path", "%s:%s does not exist (or holds no files); nothing was changed", src.name(), sp)
	}
	if err != nil {
		return xferStats{}, err
	}
	rels := make([]string, 0, len(files))
	var size int64
	count := 0
	for rel, f := range files {
		rels = append(rels, rel)
		if !f.Skip {
			count++
			size += f.Size
		}
	}
	sort.Strings(rels)
	pp := progressFrom(ctx)
	pp.total(count, size)
	st := xferStats{Dest: dst.name() + ":" + root, Source: src.name() + ":" + sp}
	from, to := src.side(cl, sp), dst.side(cl, root)
	for _, rel := range rels {
		if err := ctx.Err(); err != nil {
			return st, err // Ctrl-C: the files copied so far stay
		}
		f := files[rel]
		if f.Skip {
			st.Skipped = append(st.Skipped, rel)
			continue
		}
		if guardSensitiveRemote(cl, rel) != nil {
			cl.out.Skip(out.Skipped{Name: src.name() + ":" + path.Join(sp, rel), Kind: "file", Reason: "holds secrets; an AI agent needs --reveal, which the user allows, to copy it"})
			continue
		}
		r, err := from.open(ctx, rel)
		if err != nil {
			st.Errors = append(st.Errors, xferErr{Path: rel, Message: toErr(err).Message})
			continue
		}
		pp.start(rel)
		err = to.write(ctx, rel, pp.reader(agentScan(cl, r, src.name()+":"+path.Join(sp, rel))), f)
		r.Close()
		if ctx.Err() != nil {
			return st, ctx.Err()
		}
		if err != nil {
			st.Errors = append(st.Errors, xferErr{Path: rel, Message: toErr(err).Message})
			continue
		}
		pp.fileDone()
		st.Files++
		st.Bytes += f.Size
	}
	return st, nil
}

// agentScans: this command's copies between two remote places are read
// for vault values on their way (an AI agent without --reveal).
func agentScans(cl *call) bool { return cl.out.Mask && !cl.revealOK() }

// agentScan is r, for a copy between two remote places. The file does not
// come to this computer, but an AI agent could read it unhidden where it
// lands (a link from a bucket, another server). A download hides what
// komando hides from agents or stops; a copy cannot hide it in a file it
// does not keep, so it stops with SENSITIVE_FILE at the first such value
// (a vault value, a secret by its shape, personal data where the source
// hides it: BinaryHidden), before the destination puts the file in place.
func agentScan(cl *call, r io.Reader, where string) io.Reader {
	if !agentScans(cl) {
		return r
	}
	return &hiddenStop{cl: cl, r: r, sc: cl.out.NewValueScanner(), where: where}
}

// hiddenStop reads the stream in windows of scanStep bytes, each with the
// last scanKeep bytes before it, so a secret shape or personal data cut by
// a read is still found and BinaryHidden never sees more than it reads
// whole. Vault values are found by the value scanner beside it, which keeps
// as much as the longest one (a certificate chain may be longer than
// scanKeep).
type hiddenStop struct {
	cl    *call
	r     io.Reader
	sc    *out.ValueScanner
	tail  []byte
	where string
}

const (
	scanStep = 64 << 10
	scanKeep = 4 << 10
)

func (h *hiddenStop) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	_, _ = h.sc.Write(p[:n])
	if h.sc.Found() {
		return 0, h.refuse()
	}
	for chunk := p[:n]; len(chunk) > 0; {
		k := min(len(chunk), scanStep)
		win := append(h.tail, chunk[:k]...)
		if h.cl.out.BinaryHidden(win) {
			return 0, h.refuse()
		}
		if len(win) > scanKeep {
			win = win[len(win)-scanKeep:]
		}
		h.tail = append(h.tail[:0], win...)
		chunk = chunk[k:]
	}
	return n, err
}

// scannedEnd is a source of --continue whose reads go through agentScan:
// the part that is added is checked as it is read, so a source that
// changed after the first pass cannot bring in a hidden value.
type scannedEnd struct {
	resumeEnd
	cl *call
}

func (e scannedEnd) openAt(ctx context.Context, off int64) (io.ReadCloser, error) {
	r, err := e.resumeEnd.openAt(ctx, off)
	if err != nil {
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{agentScan(e.cl, r, e.where()), r}, nil
}

func (h *hiddenStop) refuse() error {
	return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
		revealHint(h.cl, "if the user wants it copied, run it again with --reveal"),
		"%s holds a secret or personal data komando hides from AI agents; komando does not copy it to another place for an AI agent", h.where)
}

// guardSensitiveRemote is guardSensitiveCopy for a copy between two
// remote places: the file does not come to this computer, but it lands
// where others may read it (a bucket can hand out links), so an AI agent
// needs the same yes from the user.
func guardSensitiveRemote(cl *call, p string) error {
	if !cl.isAgent() || !sensitiveName(p) || cl.revealOK() {
		return nil
	}
	return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
		revealHint(cl, "if the user wants it copied, run it again with --reveal"),
		"%s holds secrets; komando does not copy it to another place for an AI agent", p)
}
