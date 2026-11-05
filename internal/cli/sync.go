package cli

import (
	"context"
	"errors"
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
	Skip  bool // a symbolic link or special file: listed, never copied or deleted
}

// errSideMissing is what list returns when the folder (or prefix) is not
// there: a destination is then created, a source is an error.
var errSideMissing = errors.New("folder not found")

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
	if fi, err := os.Stat(l.root); os.IsNotExist(err) {
		return files, errSideMissing // a new destination folder
	} else if err == nil && !fi.IsDir() {
		return nil, out.Errf(out.ExitUsage, "NOT_A_FOLDER", "sync works on folders; for one file use `komando upload` or `komando download`", "%s is a file, not a folder", l.root)
	}
	err := filepath.WalkDir(l.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			rel, _ := filepath.Rel(l.root, p)
			files[filepath.ToSlash(rel)] = syncFile{Skip: true}
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

// agentLocalSide is localSide for an upload an AI agent runs: a file
// komando does not read for an agent (guardLocalRead) is left out and
// listed in meta.skipped. It stays in the list as skipped, so --delete
// keeps the copy on the other side. The files are checked once, before
// the hosts are worked on side by side.
type agentLocalSide struct {
	localSide
	secret map[string]bool
}

func newAgentLocalSide(ctx context.Context, root string) agentLocalSide {
	l := agentLocalSide{localSide: localSide{root: root}, secret: map[string]bool{}}
	files, _ := l.localSide.list(ctx) // an error shows when the sync lists it
	rels := make([]string, 0, len(files))
	for rel, f := range files {
		if !f.Skip {
			rels = append(rels, rel)
		}
	}
	sort.Strings(rels)
	for _, rel := range rels {
		if skipLocalSecret(filepath.Join(root, filepath.FromSlash(rel))) {
			l.secret[rel] = true
		}
	}
	return l
}

func (l agentLocalSide) list(ctx context.Context) (map[string]syncFile, error) {
	files, err := l.localSide.list(ctx)
	for rel, f := range files {
		if !f.Skip && l.secret[rel] {
			files[rel] = syncFile{Skip: true}
		}
	}
	return files, err
}

func (l agentLocalSide) open(ctx context.Context, rel string) (io.ReadCloser, error) {
	if l.secret[rel] {
		return nil, out.Errf(out.ExitPolicy, "SENSITIVE_FILE", "the file was left out; an AI agent needs --reveal, which the user allows, to send it", "%s holds secrets; komando does not send it for an AI agent", rel)
	}
	return l.localSide.open(ctx, rel)
}

func (l localSide) open(_ context.Context, rel string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(l.root, filepath.FromSlash(rel)))
}

func (l localSide) write(_ context.Context, rel string, r io.Reader, f syncFile) error {
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return out.Errf(out.ExitRemote, "UNSAFE_PATH", "nothing outside the folder was written; check the source for odd file names", "the source sent the path %q, which leads outside %s", rel, l.root)
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
	if fi, err := s.sc.Stat(s.root); err != nil {
		if os.IsNotExist(err) {
			return files, errSideMissing
		}
		return nil, fsErrHint(s.root, err, syncPermHint)
	} else if !fi.IsDir() {
		return nil, out.Errf(out.ExitUsage, "NOT_A_FOLDER", "sync works on folders; for one file use `komando download` or `komando upload`", "%s is a file, not a folder", s.root)
	}
	w := s.sc.Walk(s.root)
	for w.Step() {
		if w.Err() != nil {
			return nil, fsErrHint(w.Path(), w.Err(), syncPermHint)
		}
		if w.Stat().IsDir() {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(w.Path(), s.root), "/")
		if !w.Stat().Mode().IsRegular() {
			files[rel] = syncFile{Skip: true}
			continue
		}
		files[rel] = syncFile{Size: w.Stat().Size(), Mtime: w.Stat().ModTime(), Mode: w.Stat().Mode().Perm()}
	}
	return files, nil
}

const syncPermHint = "sync reads and writes as the SSH user; fix the owner or permissions, or --exclude it"

func (s sftpSide) open(_ context.Context, rel string) (io.ReadCloser, error) {
	f, err := s.sc.Open(path.Join(s.root, rel))
	if err != nil {
		return nil, fsErr(rel, err)
	}
	return f, nil
}

func (s sftpSide) write(_ context.Context, rel string, r io.Reader, f syncFile) error {
	if strings.Contains("/"+rel+"/", "/../") {
		return out.Errf(out.ExitUsage, "UNSAFE_PATH", "nothing outside the folder was written; rename the file so it has no .. in its path", "path %q leads outside %s", rel, s.root)
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
		if toErr(err).Exit == out.ExitNotFound {
			return map[string]syncFile{}, errSideMissing // SFTP/FTP: the folder is not there yet
		}
		return nil, err
	}
	if more {
		return nil, out.Usage("more than a million objects under %q; sync a smaller prefix", b.prefix)
	}
	files := map[string]syncFile{}
	for _, o := range objs {
		rel := strings.TrimPrefix(o.Key, b.prefix)
		// folder markers: the prefix itself, or a key ending in / (S3
		// consoles create them); they hold no file
		if o.Dir || rel == "" || strings.HasSuffix(rel, "/") || o.Key+"/" == b.prefix {
			continue
		}
		files[rel] = syncFile{Size: o.Size, Mtime: o.Modified}
	}
	if len(files) == 0 {
		return files, errSideMissing // nothing under the prefix: S3 has no empty folders
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
	Skipped   []string     `json:"skipped,omitempty"`    // symbolic links and special files in SRC, not copied
	NewFolder bool         `json:"new_folder,omitempty"` // DST did not exist: it is (or would be) created
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
		if f.Skip || excluded(rel, o.exclude) {
			continue
		}
		d, ok := dst[rel]
		switch {
		case !ok || d.Skip:
			acts = append(acts, syncAction{Op: "copy", Path: rel, Size: f.Size})
		case d.Size != f.Size || f.Mtime.After(d.Mtime.Add(2*time.Second)) || f.Mode != 0 && d.Mode != 0 && f.Mode != d.Mode:
			if o.onlyNew {
				acts = append(acts, syncAction{Op: "keep", Path: rel})
			} else {
				acts = append(acts, syncAction{Op: "update", Path: rel, Size: f.Size})
			}
		}
	}
	if o.delete {
		for rel, d := range dst {
			if _, ok := src[rel]; !ok && !d.Skip && !excluded(rel, o.exclude) {
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
	if errors.Is(err, errSideMissing) {
		return nil, out.Errf(out.ExitNotFound, "PATH_NOT_FOUND", "check the source path; nothing was changed", "%s does not exist (or holds no files)", srcName)
	}
	if err != nil {
		return nil, err
	}
	df, err := dst.list(ctx)
	newFolder := errors.Is(err, errSideMissing)
	if err != nil && !newFolder {
		return nil, err
	}
	res := &syncResult{Src: srcName, Dst: dstName, DryRun: g.dryRun, Actions: []syncAction{}, NewFolder: newFolder}
	files := 0
	for rel, f := range sf {
		switch {
		case f.Skip:
			res.Skipped = append(res.Skipped, rel)
		case !excluded(rel, o.exclude):
			files++
		}
	}
	sort.Strings(res.Skipped)
	if o.delete && files == 0 && len(df) > 0 {
		// an empty source would make --delete wipe the destination
		return nil, out.Errf(out.ExitNotFound, "SOURCE_EMPTY", "check the source path; nothing was deleted",
			"%s has no files to sync, so --delete would remove everything in %s", srcName, dstName)
	}
	acts := planSync(sf, df, o)
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
	res.Unchanged = files - res.Copied - res.Updated - res.Kept
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

var syncPast = map[string]string{"copy": "copied", "update": "updated", "delete": "deleted"}

func (r *syncResult) Text() string {
	var sb strings.Builder
	if r.Host != "" {
		fmt.Fprintf(&sb, "● %s\n", r.Host)
	}
	if r.NewFolder {
		if r.DryRun {
			sb.WriteString("  would create the folder " + r.Dst + "\n")
		} else {
			sb.WriteString("  created the folder " + r.Dst + "\n")
		}
	}
	for _, a := range r.Actions {
		if a.Op == "keep" {
			continue
		}
		if r.DryRun {
			fmt.Fprintf(&sb, "  would %-6s %s\n", a.Op, a.Path)
		} else {
			fmt.Fprintf(&sb, "  %-7s %s\n", syncPast[a.Op], a.Path)
		}
	}
	if r.More {
		sb.WriteString("  ... (more; see -o json)\n")
	}
	if r.DryRun {
		fmt.Fprintf(&sb, "would copy %d, update %d, delete %d; %d unchanged (%s)\n", r.Copied, r.Updated, r.Deleted, r.Unchanged, humanBytes(r.Bytes))
	} else {
		fmt.Fprintf(&sb, "copied %d, updated %d, deleted %d; %d unchanged (%s)\n", r.Copied, r.Updated, r.Deleted, r.Unchanged, humanBytes(r.Bytes))
	}
	if r.Kept > 0 {
		fmt.Fprintf(&sb, "kept %d existing local files (--overwrite replaces them)\n", r.Kept)
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintf(&sb, "skipped %d symbolic link(s) or special file(s): %s\n", len(r.Skipped), shortList(r.Skipped, 5))
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
			srcT, srcP, srcRemote := splitArg(args[0])
			dstT, dstP, dstRemote := splitArg(args[1])
			switch {
			case srcRemote && dstRemote:
				return out.Usage("one side must be a folder on this computer; sync remote to remote by way of a local folder")
			case !srcRemote && !dstRemote:
				return out.Usage("one side must be remote: TARGET:PATH (servers) or CONN:PREFIX (storage); a local name with a colon is written ./name")
			}
			if !srcRemote {
				fi, err := os.Stat(srcP)
				if err != nil {
					return localFileErr("PATH_NOT_FOUND", err, "")
				}
				if !fi.IsDir() {
					return out.Errf(out.ExitUsage, "NOT_A_FOLDER", "sync copies folders; for one file use `komando upload`", "%s is a file, not a folder", srcP)
				}
			}
			if dstRemote {
				return colonHint(syncUp(cmd.Context(), "sync", srcP, dstT, dstP, o), args[1])
			}
			return colonHint(syncDown(cmd.Context(), "sync", srcT, srcP, dstP, o), args[0])
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
	if err := guardLocalRead(local); err != nil {
		return err
	}
	var src syncSide = localSide{root: local}
	if isAgent() {
		// each file is checked as cp -r does: komando's own data and private
		// keys stay here even under a folder that holds them (sync ~ web:),
		// and files that are secrets by name too, unless the user allows
		// --reveal, as syncDown leaves them there
		src = newAgentLocalSide(ctx, local)
	}
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
		r, err := runSync(ctx, src, sftpSide{sc: sc, root: expandRemote(sc, remote)}, local, c.Host.Name+":"+remote, o)
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
	h, err := oneServer(st, target, "sync downloads from one server; name one, e.g. `komando sync SERVER:"+remote+" "+local+"`")
	if err != nil {
		return err
	}
	res := fanout(ctx, st, []*store.Host{h}, func(ctx context.Context, c *sshx.Client) (any, error) {
		sc, err := sftpClient(c)
		if err != nil {
			return nil, err
		}
		defer sc.Close()
		r, err := runSync(ctx, sftpSide{sc: sc, root: expandRemote(sc, remote)}, dst, c.Host.Name+":"+remote, local, o)
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
			if len(f.Results) == 1 {
				continue // the closing error line says it
			}
			e, _ := v["error"].(*out.Error)
			if e == nil {
				fmt.Fprintf(&sb, "● %v  FAILED\n", v["host"])
				continue
			}
			fmt.Fprintf(&sb, "● %v  FAILED [%s] %s\n", v["host"], e.Code, e.Message)
			if e.Hint != "" {
				sb.WriteString("  hint: " + e.Hint + "\n")
			}
		}
	}
	return sb.String()
}

func finishSync(st *store.State, name string, hosts []*store.Host, res []outcome, src, dst string) error {
	data := syncFleet{Results: []any{}}
	worst := 0
	var fails []hostFail
	for _, o := range res {
		data.Summary.Total++
		if o.Err != nil {
			e := toErr(o.Err)
			worst = worse(worst, e.Exit)
			fails = append(fails, hostFail{host: o.Host.Name, reason: failReason(0, e), err: e})
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
	return finishFleet(name, data, runSummary{fleetSummary: data.Summary}, worst, fails)
}
