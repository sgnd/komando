package cli

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"os"
	"path"
	"path/filepath"
	"sort"
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

// `komando sync` copies a folder one way: from this computer to servers or
// storage, or from a server or storage to this computer. Only files that
// are new or changed (size, or a newer modification time) are sent;
// --delete also removes what the source no longer has.

// syncFile is one file in a tree, by its path relative to the root.
type syncFile struct {
	Size  int64
	Mtime time.Time
	Mode  fs.FileMode
}

// syncSide is one end of a sync: a local folder, a folder on a server, or a
// prefix in a storage conn.
type syncSide interface {
	list(ctx context.Context) (map[string]syncFile, error)
	open(ctx context.Context, rel string) (io.ReadCloser, error)
	write(ctx context.Context, rel string, r io.Reader, f syncFile) error
	remove(ctx context.Context, rel string) error
}

// --- this computer --------------------------------------------------------

type localSide struct{ root string }

func (l localSide) list(context.Context) (map[string]syncFile, error) {
	files := map[string]syncFile{}
	if _, err := os.Stat(l.root); os.IsNotExist(err) {
		return files, nil // a new destination folder
	}
	err := filepath.WalkDir(l.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(l.root, p)
		files[filepath.ToSlash(rel)] = syncFile{Size: fi.Size(), Mtime: fi.ModTime(), Mode: fi.Mode().Perm()}
		return nil
	})
	return files, err
}

func (l localSide) open(_ context.Context, rel string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(l.root, filepath.FromSlash(rel)))
}

func (l localSide) write(_ context.Context, rel string, r io.Reader, f syncFile) error {
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return out.Errf(out.ExitRemote, "UNSAFE_PATH", "", "the source sent the path %q, which leads outside %s", rel, l.root)
	}
	dst := filepath.Join(l.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".komando-sync-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = io.Copy(tmp, r)
	mode := f.Mode
	if mode == 0 {
		mode = 0o644
	}
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if !f.Mtime.IsZero() {
		_ = os.Chtimes(tmp.Name(), f.Mtime, f.Mtime) // the next sync sees it as unchanged
	}
	return os.Rename(tmp.Name(), dst)
}

func (l localSide) remove(_ context.Context, rel string) error {
	return os.Remove(filepath.Join(l.root, filepath.FromSlash(rel)))
}

// --- a folder on a server, over SFTP ---------------------------------------

type sftpSide struct {
	sc   *sftp.Client
	root string
}

func (s sftpSide) list(context.Context) (map[string]syncFile, error) {
	files := map[string]syncFile{}
	if _, err := s.sc.Stat(s.root); err != nil {
		if os.IsNotExist(err) {
			return files, nil
		}
		return nil, fsErr(s.root, err)
	}
	w := s.sc.Walk(s.root)
	for w.Step() {
		if w.Err() != nil {
			return nil, fsErr(w.Path(), w.Err())
		}
		if !w.Stat().Mode().IsRegular() {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(w.Path(), s.root), "/")
		files[rel] = syncFile{Size: w.Stat().Size(), Mtime: w.Stat().ModTime(), Mode: w.Stat().Mode().Perm()}
	}
	return files, nil
}

func (s sftpSide) open(_ context.Context, rel string) (io.ReadCloser, error) {
	f, err := s.sc.Open(path.Join(s.root, rel))
	if err != nil {
		return nil, fsErr(rel, err)
	}
	return f, nil
}

func (s sftpSide) write(_ context.Context, rel string, r io.Reader, f syncFile) error {
	if strings.Contains("/"+rel+"/", "/../") {
		return out.Errf(out.ExitUsage, "UNSAFE_PATH", "", "path %q leads outside %s", rel, s.root)
	}
	dst := path.Join(s.root, rel)
	if err := s.sc.MkdirAll(path.Dir(dst)); err != nil {
		return fsErr(path.Dir(dst), err)
	}
	tmp := path.Join(path.Dir(dst), fmt.Sprintf(".komando-sync-%d-%s", time.Now().UnixNano(), path.Base(dst)))
	o, err := s.sc.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fsErr(tmp, err)
	}
	_, err = io.Copy(o, r)
	if cerr := o.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		s.sc.Remove(tmp)
		return err
	}
	if f.Mode != 0 {
		_ = s.sc.Chmod(tmp, f.Mode)
	}
	if !f.Mtime.IsZero() {
		_ = s.sc.Chtimes(tmp, f.Mtime, f.Mtime)
	}
	if err := s.sc.PosixRename(tmp, dst); err != nil {
		if err2 := s.sc.Rename(tmp, dst); err2 != nil {
			s.sc.Remove(tmp)
			return fsErr(dst, err)
		}
	}
	return nil
}

func (s sftpSide) remove(_ context.Context, rel string) error {
	return fsErr(rel, s.sc.Remove(path.Join(s.root, rel)))
}

// --- a prefix in a storage conn ---------------------------------------------

type bucketSide struct {
	b      storex.Bucket
	prefix string // "" or "folder/" inside the conn
}

func (b bucketSide) key(rel string) string { return b.prefix + rel }

func (b bucketSide) list(ctx context.Context) (map[string]syncFile, error) {
	objs, more, err := b.b.List(ctx, b.prefix, true, 1_000_000)
	if err != nil {
		return nil, err
	}
	if more {
		return nil, out.Usage("more than a million objects under %q; sync a smaller prefix", b.prefix)
	}
	files := map[string]syncFile{}
	for _, o := range objs {
		if o.Dir {
			continue
		}
		files[strings.TrimPrefix(o.Key, b.prefix)] = syncFile{Size: o.Size, Mtime: o.Modified}
	}
	return files, nil
}

func (b bucketSide) open(ctx context.Context, rel string) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	go func() {
		_, err := b.b.Get(ctx, b.key(rel), pw)
		pw.CloseWithError(err)
	}()
	return pr, nil
}

func (b bucketSide) write(ctx context.Context, rel string, r io.Reader, f syncFile) error {
	return b.b.Put(ctx, b.key(rel), r, f.Size, mime.TypeByExtension(path.Ext(rel)))
}

func (b bucketSide) remove(ctx context.Context, rel string) error {
	return b.b.Remove(ctx, b.key(rel))
}

// --- planning ---------------------------------------------------------------

type syncOpts struct {
	delete, onlyNew bool
	exclude         []string
}

type syncAction struct {
	Op   string `json:"op"` // copy (new), update (changed), delete, keep (exists; downloads that never replace)
	Path string `json:"path"`
	Size int64  `json:"size,omitempty"`
}

type syncResult struct {
	Src       string       `json:"src"`
	Dst       string       `json:"dst"`
	Host      string       `json:"host,omitempty"`
	Copied    int          `json:"copied"`
	Updated   int          `json:"updated"`
	Deleted   int          `json:"deleted"`
	Kept      int          `json:"kept,omitempty"`
	Unchanged int          `json:"unchanged"`
	Bytes     int64        `json:"bytes"`
	Actions   []syncAction `json:"actions"`
	More      bool         `json:"more_actions,omitempty"`
	DryRun    bool         `json:"dry_run,omitempty"`
}

// excluded matches a path, or any of its folders, against the patterns
// (shell globs: *.log, node_modules, .git).
func excluded(rel string, patterns []string) bool {
	parts := strings.Split(rel, "/")
	for _, p := range patterns {
		if ok, _ := path.Match(p, rel); ok {
			return true
		}
		for _, part := range parts {
			if ok, _ := path.Match(p, part); ok {
				return true
			}
		}
	}
	return false
}

// planSync decides what to do with every path. A file is sent when the
// destination lacks it, its size differs, or the source is newer (more than
// 2 s: FAT and some servers round times).
func planSync(src, dst map[string]syncFile, o syncOpts) []syncAction {
	var acts []syncAction
	for rel, f := range src {
		if excluded(rel, o.exclude) {
			continue
		}
		d, ok := dst[rel]
		switch {
		case !ok:
			acts = append(acts, syncAction{Op: "copy", Path: rel, Size: f.Size})
		case d.Size != f.Size || f.Mtime.After(d.Mtime.Add(2*time.Second)):
			if o.onlyNew {
				acts = append(acts, syncAction{Op: "keep", Path: rel})
			} else {
				acts = append(acts, syncAction{Op: "update", Path: rel, Size: f.Size})
			}
		}
	}
	if o.delete {
		for rel := range dst {
			if _, ok := src[rel]; !ok && !excluded(rel, o.exclude) {
				acts = append(acts, syncAction{Op: "delete", Path: rel})
			}
		}
	}
	sort.Slice(acts, func(i, j int) bool { return acts[i].Path < acts[j].Path })
	return acts
}

// runSync plans and (unless dry-run) carries out one sync.
func runSync(ctx context.Context, src, dst syncSide, srcName, dstName string, o syncOpts) (*syncResult, error) {
	sf, err := src.list(ctx)
	if err != nil {
		return nil, err
	}
	df, err := dst.list(ctx)
	if err != nil {
		return nil, err
	}
	acts := planSync(sf, df, o)
	res := &syncResult{Src: srcName, Dst: dstName, DryRun: g.dryRun, Actions: []syncAction{}}
	for _, a := range acts {
		switch a.Op {
		case "copy":
			res.Copied++
			res.Bytes += a.Size
		case "update":
			res.Updated++
			res.Bytes += a.Size
		case "delete":
			res.Deleted++
		case "keep":
			res.Kept++
		}
	}
	res.Unchanged = len(sf) - res.Copied - res.Updated - res.Kept
	for rel := range sf {
		if excluded(rel, o.exclude) {
			res.Unchanged--
		}
	}
	const shown = 1000
	res.Actions = acts
	if len(acts) > shown {
		res.Actions, res.More = acts[:shown], true
	}
	if g.dryRun {
		return res, nil
	}
	for _, a := range acts {
		switch a.Op {
		case "copy", "update":
			r, err := src.open(ctx, a.Path)
			if err != nil {
				return res, err
			}
			err = dst.write(ctx, a.Path, r, sf[a.Path])
			r.Close()
			if err != nil {
				return res, fmt.Errorf("%s: %w", a.Path, err)
			}
		case "delete":
			if err := dst.remove(ctx, a.Path); err != nil {
				return res, fmt.Errorf("%s: %w", a.Path, err)
			}
		}
	}
	return res, nil
}

func (r *syncResult) Text() string {
	var sb strings.Builder
	if r.Host != "" {
		fmt.Fprintf(&sb, "● %s\n", r.Host)
	}
	verb := map[bool]string{true: "would ", false: ""}[r.DryRun]
	for _, a := range r.Actions {
		if a.Op != "keep" {
			fmt.Fprintf(&sb, "  %s%-6s %s\n", verb, a.Op, a.Path)
		}
	}
	fmt.Fprintf(&sb, "%scopied %d, updated %d, deleted %d, unchanged %d (%s)\n", verb, r.Copied, r.Updated, r.Deleted, r.Unchanged, humanBytes(r.Bytes))
	if r.Kept > 0 {
		fmt.Fprintf(&sb, "kept %d existing local files (--overwrite replaces them)\n", r.Kept)
	}
	return sb.String()
}

// --- the command --------------------------------------------------------------

func syncCmd() *cobra.Command {
	var o syncOpts
	c := &cobra.Command{
		Use:   "sync SRC DST",
		Short: "Copy a folder one way, sending only new and changed files (servers, storage, this computer)",
		Long: `One side is a folder on this computer; the other is TARGET:PATH on servers
(many at once: @web:/var/www/site) or CONN:PREFIX in storage (S3, FTP/FTPS,
SFTP). Files that are new, a different size, or newer in SRC are copied; the
rest are left alone. --delete also removes files SRC no longer has (that
needs --allow-dangerous). --exclude skips names or paths (shell globs,
repeatable). Try --dry-run first: it lists every file it would touch.`,
		Example: `  komando sync ./site @web:/var/www/site --exclude .git --dry-run
  komando sync ./site web1:/var/www/site --delete --allow-dangerous
  komando sync ./backups backups:2026/ --exclude '*.tmp'
  komando sync backups:2026/ ./restore
  komando sync web1:/var/log/app ./logs/web1`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			srcT, srcP, srcRemote := splitRemote(args[0])
			dstT, dstP, dstRemote := splitRemote(args[1])
			switch {
			case srcRemote && dstRemote:
				return out.Usage("one side must be a folder on this computer; sync remote to remote by way of a local folder")
			case !srcRemote && !dstRemote:
				return out.Usage("one side must be remote: TARGET:PATH (servers) or CONN:PREFIX (storage)")
			}
			if !srcRemote {
				if fi, err := os.Stat(srcP); err != nil || !fi.IsDir() {
					return out.Errf(out.ExitNotFound, "PATH_NOT_FOUND", "sync copies folders; for one file use `komando upload`", "%s is not a folder on this computer", srcP)
				}
			}
			if dstRemote {
				return syncUp(cmd.Context(), "sync", srcP, dstT, dstP, o)
			}
			return syncDown(cmd.Context(), "sync", srcT, srcP, dstP, o)
		},
	}
	c.Flags().BoolVar(&o.delete, "delete", false, "also remove files that SRC does not have (needs --allow-dangerous)")
	c.Flags().StringArrayVar(&o.exclude, "exclude", nil, "skip names or paths matching this glob (repeatable), e.g. .git, '*.log'")
	return c
}

// guardDelete: --delete removes files for good, like `storage rm`.
func guardDelete(o syncOpts) error {
	if o.delete && !dangerOK() && !g.dryRun {
		return out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "check the list with --dry-run, confirm with the user, then add --allow-dangerous",
			"--delete removes files in the destination that the source does not have")
	}
	return nil
}

// syncUp sends a local folder to servers or to a storage conn.
func syncUp(ctx context.Context, name, local, target, remote string, o syncOpts) error {
	storage, err := fileTarget(target)
	if err != nil {
		return err
	}
	if err := guardDelete(o); err != nil {
		return err
	}
	src := localSide{root: local}
	if storage {
		v := driver.Verdict{Risk: driver.RiskWrite}
		if o.delete {
			v = driver.DataDelete()
		}
		return syncStorage(ctx, name, target, v, func(ctx context.Context, c *store.Conn, b storex.Bucket) (any, error) {
			return runSync(ctx, src, bucketSide{b: b, prefix: folderKey(remote)}, local, c.Name+":"+remote, o)
		})
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return err
	}
	if err := guard(st, hosts, "", true); err != nil {
		return err
	}
	res := fanout(ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		sc, err := sftpClient(c)
		if err != nil {
			return nil, err
		}
		defer sc.Close()
		r, err := runSync(ctx, src, sftpSide{sc: sc, root: remote}, local, c.Host.Name+":"+remote, o)
		if r != nil {
			r.Host = c.Host.Name
		}
		return r, err
	})
	return finishSync(st, name, hosts, res, local, target+":"+remote)
}

// syncDown fetches a folder from one server or a storage conn.
func syncDown(ctx context.Context, name, target, remote, local string, o syncOpts) error {
	storage, err := fileTarget(target)
	if err != nil {
		return err
	}
	if err := guardDelete(o); err != nil {
		return err
	}
	if isAgent() && !revealOK() {
		// files that are secrets by name stay where they are (sensitive.go)
		o.exclude = append(o.exclude, sensitiveGlobs...)
	}
	dst := localSide{root: local}
	if storage {
		return syncStorage(ctx, name, target, driver.Verdict{}, func(ctx context.Context, c *store.Conn, b storex.Bucket) (any, error) {
			return runSync(ctx, bucketSide{b: b, prefix: folderKey(remote)}, dst, c.Name+":"+remote, local, o)
		})
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	h, err := singleHost(st, target)
	if err != nil {
		return err
	}
	res := fanout(ctx, st, []*store.Host{h}, func(ctx context.Context, c *sshx.Client) (any, error) {
		sc, err := sftpClient(c)
		if err != nil {
			return nil, err
		}
		defer sc.Close()
		r, err := runSync(ctx, sftpSide{sc: sc, root: remote}, dst, c.Host.Name+":"+remote, local, o)
		if r != nil {
			r.Host = c.Host.Name
		}
		return r, err
	})
	return finishSync(st, name, []*store.Host{h}, res, target+":"+remote, local)
}

// syncStorage runs a sync against one storage conn. Unlike other storage
// changes, a dry run still reads both sides, so it can list the files.
func syncStorage(ctx context.Context, name, connExpr string, v driver.Verdict, fn func(ctx context.Context, c *store.Conn, b storex.Bucket) (any, error)) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "storage")
	if err != nil {
		return err
	}
	if v.Risk > driver.RiskRead && !g.dryRun {
		if err := guardConns(st, []*store.Conn{c}, v); err != nil {
			return err
		}
	}
	if g.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.timeout)
		defer cancel()
	}
	b, err := openBucket(ctx, st, c)
	if err != nil {
		return err
	}
	defer b.Close()
	data, err := fn(ctx, c, b)
	r, _ := data.(*syncResult)
	rec := map[string]any{"conns": []string{c.Name}, "risk": v.Risk.String()}
	if r != nil {
		rec["copied"], rec["updated"], rec["deleted"] = r.Copied, r.Updated, r.Deleted
	}
	if v.Risk > driver.RiskRead || (r != nil && !r.DryRun) {
		audit(st, name, nil, "", err == nil, rec)
	}
	if err != nil {
		return toErr(err)
	}
	out.P.Print(name, data, nil)
	return nil
}

// folderKey turns a storage prefix into "folder/" ("" for the conn's root).
func folderKey(p string) string {
	p = strings.Trim(p, "/")
	if p == "" || p == "." {
		return ""
	}
	return p + "/"
}

type syncFleet struct {
	Results []any        `json:"results"`
	Summary fleetSummary `json:"summary"`
}

func (f syncFleet) Text() string {
	var sb strings.Builder
	for _, r := range f.Results {
		switch v := r.(type) {
		case *syncResult:
			sb.WriteString(v.Text())
		case map[string]any:
			fmt.Fprintf(&sb, "● %v  FAILED: %v\n", v["host"], v["error"])
		}
	}
	return sb.String()
}

func finishSync(st *store.State, name string, hosts []*store.Host, res []outcome, src, dst string) error {
	data := syncFleet{Results: []any{}}
	worst := 0
	for _, o := range res {
		data.Summary.Total++
		if o.Err != nil {
			e := toErr(o.Err)
			worst = worse(worst, e.Exit)
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, o.Host.Name)
			data.Results = append(data.Results, map[string]any{"host": o.Host.Name, "ok": false, "error": e})
			continue
		}
		data.Summary.OK++
		data.Results = append(data.Results, o.Value)
	}
	if !g.dryRun {
		audit(st, name, hostNames(hosts), "", data.Summary.Failed == 0, map[string]any{"src": src, "dst": dst})
	}
	return finish(name, data, data.Summary, worst)
}
