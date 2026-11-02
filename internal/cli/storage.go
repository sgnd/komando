package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// Storage commands work with S3-compatible buckets and FTP/FTPS/SFTP
// folders through one interface. Like files on a server: ls and download
// read, upload and rm change (protected conns need --yes), and downloads
// never overwrite a local file.

func storageCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "storage",
		Aliases: []string{"s3"},
		Short:   "Files in buckets and on file servers (S3, MinIO, R2, FTPS, SFTP): list, download, upload, share",
		Long: `Work with a storage conn (see ` + "`komando conn`" + `): an S3-compatible bucket, or a
folder on an FTPS, FTP or SFTP server. Keys are relative to the folder in the
conn URL. ls and download only read. upload changes files and link shares one
(S3 only; protected conns need --yes for both); rm deletes, so it also needs
--allow-dangerous. Downloads never overwrite a local file, and uploads to file
servers go to a temporary name first, so a failed upload leaves nothing half
written.`,
	}
	c.AddCommand(storageLsCmd(), storageCatCmd(), storageDownloadCmd(), storageUploadCmd(), storageRmCmd(), storageLinkCmd())
	return c
}

// withStorage resolves the conn, applies the seatbelts for v, runs fn and
// audits the action. Dry runs of changes stop before contacting the server.
func withStorage(ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error)) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "storage")
	if err != nil {
		return err
	}
	rec["conns"], rec["risk"] = []string{c.Name}, v.Risk.String()
	fail := func(err error) error {
		rec["error"] = toErr(err).Code
		audit(st, name, nil, "", false, rec)
		return err
	}
	if v.Risk > driver.RiskRead {
		if err := guardConns(st, []*store.Conn{c}, v); err != nil {
			return fail(err)
		}
		if g.dryRun {
			audit(st, name, nil, "", true, rec)
			out.P.Print(name, map[string]any{"conn": c.Name, "risk": v.Risk.String(), "dry_run": true, "note": "nothing sent: the change would be allowed"}, nil)
			return nil
		}
	}
	if g.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.timeout)
		defer cancel()
	}
	s, err := openBucket(ctx, st, c)
	if err != nil {
		return fail(err)
	}
	defer s.Close()
	data, err := fn(ctx, c, s)
	if err != nil {
		return fail(err)
	}
	audit(st, name, nil, "", true, rec)
	out.P.Print(name, data, nil)
	return nil
}

// openBucket connects to a storage conn of any kind.
func openBucket(ctx context.Context, st *store.State, c *store.Conn) (storex.Bucket, error) {
	t, err := driver.Parse(c.URL)
	if err != nil {
		return nil, err
	}
	if t.Kind.Name == "sftp" {
		// an SFTP server is an SSH host without a shell: dial it like one, so
		// host keys, keys/agent and the --via chain work exactly as for hosts
		h := sftpHost(c)
		cctx, cancel := context.WithTimeout(ctx, sshOpts(st).ConnectTimeout)
		defer cancel()
		sc, err := sshx.Dial(cctx, st, h, sshOpts(st))
		if err != nil {
			return nil, err
		}
		cl, err := sftp.NewClient(sc.Client)
		if err != nil {
			sc.Close()
			return nil, out.Errf(out.ExitConnect, "STORAGE_CONNECT", "the server accepted SSH but offers no SFTP", "%v", err)
		}
		return storex.NewSFTP(cl, t.Prefix, sc.Close), nil
	}
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return nil, err
	}
	var b storex.Bucket
	switch t.Kind.Name {
	case "s3":
		b, err = storex.OpenS3(a.Target, a.Password, a.Dial, dbTimeout())
	default: // ftp, ftps
		b, err = storex.OpenFTP(ctx, a.Target, a.Password, a.Dial, dbTimeout())
	}
	if err != nil {
		a.Close()
		return nil, err
	}
	return closeBoth{b, a.Close}, nil
}

// closeBoth closes a bucket and then the connection path it uses.
type closeBoth struct {
	storex.Bucket
	after func()
}

func (c closeBoth) Close() error {
	err := c.Bucket.Close()
	c.after()
	return err
}

type objectList struct {
	Conn    string          `json:"conn"`
	Prefix  string          `json:"prefix"`
	Objects []storex.Object `json:"objects"`
	Count   int             `json:"count"`
	More    bool            `json:"more"`
}

func (l objectList) Text() string {
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
	for _, o := range l.Objects {
		if o.Dir {
			fmt.Fprintf(tw, "DIR\t\t%s\n", o.Key)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", humanBytes(o.Size), o.Modified.Format("2006-01-02 15:04"), o.Key)
	}
	tw.Flush()
	if l.More {
		fmt.Fprintf(&sb, "(first %d; more exist: narrow the prefix or raise --limit)\n", l.Count)
	}
	return sb.String()
}

func storageLsCmd() *cobra.Command {
	var recursive bool
	var limit int
	c := &cobra.Command{
		Use:     "ls CONN [PREFIX]",
		Aliases: []string{"list"},
		Short:   "List objects and folders (one level, or everything with --recursive)",
		Example: `  komando storage ls backups
  komando storage ls backups db/2026-11/ --recursive`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix := ""
			if len(args) == 2 {
				prefix = args[1]
			}
			return withStorage(cmd.Context(), "storage.ls", args[0], driver.Verdict{}, map[string]any{"prefix": prefix},
				func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					objs, more, err := s.List(ctx, prefix, recursive, limit)
					if err != nil {
						return nil, err
					}
					return objectList{Conn: c.Name, Prefix: prefix, Objects: objs, Count: len(objs), More: more}, nil
				})
		},
	}
	c.Flags().BoolVarP(&recursive, "recursive", "r", false, "include everything below the prefix, not just one level")
	c.Flags().IntVarP(&limit, "limit", "n", 1000, "max entries returned")
	return c
}

func storageDownloadCmd() *cobra.Command {
	var to string
	c := &cobra.Command{
		Use:     "download CONN KEY",
		Aliases: []string{"get"},
		Short:   "Same as `komando download CONN KEY`",
		Example: `  komando storage download backups db/app-2026-11-02.sql.gz
  komando storage download backups reports/q3.pdf --to ~/Downloads/q3.pdf`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return storageDownload(cmd.Context(), "storage.download", args[0], args[1], to)
		},
	}
	c.Flags().StringVar(&to, "to", "", "file to create (default: the key's file name in the current folder)")
	return c
}

func storageUploadCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "upload CONN FILE [KEY]",
		Aliases: []string{"put"},
		Short:   "Same as `komando upload CONN FILE [KEY]`",
		Example: `  komando storage upload backups prod-2026-11-02.sql.gz
  komando storage upload backups ./report.pdf reports/2026/q3.pdf`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := ""
			if len(args) == 3 {
				key = args[2]
			}
			return storageUpload(cmd.Context(), "storage.upload", args[0], args[1], key)
		},
	}
	return c
}

func storageRmCmd() *cobra.Command {
	var prefix, olderThan string
	var limit int
	c := &cobra.Command{
		Use:   "rm CONN [KEY...]",
		Short: "Delete objects by exact key, or everything under --prefix (optionally --older-than); needs --allow-dangerous",
		Long: `Without --prefix, rm takes exact keys (no patterns). With --prefix it removes
every object under that folder, or with --older-than only the ones older
than that (30d, 12h): the usual cleanup of old backups. --dry-run lists them
first; --limit (default 1000) refuses to go on when more would be removed.`,
		Example: `  komando storage rm backups tmp/old.sql.gz --allow-dangerous
  komando storage rm backups --prefix daily/ --older-than 30d --dry-run
  komando storage rm backups --prefix daily/ --older-than 30d --allow-dangerous`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keys := args[1:]
			if prefix == "" && olderThan != "" {
				return out.Usage("--older-than goes with --prefix (use --prefix / for the whole conn)")
			}
			if prefix == "" && len(keys) == 0 {
				return out.Usage("give exact keys, or --prefix FOLDER/")
			}
			if prefix != "" && len(keys) > 0 {
				return out.Usage("give keys or --prefix, not both")
			}
			for _, k := range keys {
				if strings.HasSuffix(k, "/") || strings.ContainsAny(k, "*?") {
					return out.Usage("%q looks like a folder or pattern; use --prefix for folders (see `komando storage ls`)", k)
				}
			}
			var age time.Duration
			if olderThan != "" {
				var err error
				if age, err = parseAge(olderThan); err != nil {
					return err
				}
			}
			rec := map[string]any{"keys": keys, "prefix": prefix, "older_than": olderThan}
			if prefix != "" {
				// list first, even in a dry run: the answer is the list
				return storageRmPrefix(cmd.Context(), args[0], folderKey(prefix), age, limit, rec)
			}
			return withStorage(cmd.Context(), "storage.rm", args[0], driver.DataDelete(), rec,
				func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					done, err := removeKeys(ctx, s, keys)
					rec["deleted"] = done
					if err != nil {
						return nil, err
					}
					return map[string]any{"conn": c.Name, "deleted": done}, nil
				})
		},
	}
	c.Flags().StringVar(&prefix, "prefix", "", "remove everything under this folder (e.g. daily/; / for the whole conn)")
	c.Flags().StringVar(&olderThan, "older-than", "", "with --prefix: only objects older than this (30d, 12h, 90m)")
	c.Flags().IntVarP(&limit, "limit", "n", 1000, "refuse when more than this many objects would be removed")
	return c
}

// parseAge reads durations with days (30d) as well as Go units (12h).
func parseAge(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(d); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, nil
	}
	return 0, out.Usage("--older-than takes an age like 30d, 12h or 90m")
}

func removeKeys(ctx context.Context, s storex.Bucket, keys []string) ([]string, error) {
	done := []string{}
	for _, k := range keys {
		if err := s.Remove(ctx, k); err != nil {
			e := toErr(err)
			if len(done) > 0 {
				e.Message += fmt.Sprintf(" (already deleted: %d)", len(done))
			}
			return done, e
		}
		done = append(done, k)
	}
	return done, nil
}

// storageRmPrefix lists what is under prefix (and older than age), shows
// it in a dry run, and removes it otherwise.
func storageRmPrefix(ctx context.Context, connExpr, prefix string, age time.Duration, limit int, rec map[string]any) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "storage")
	if err != nil {
		return err
	}
	if !g.dryRun {
		if err := guardConns(st, []*store.Conn{c}, driver.DataDelete()); err != nil {
			return err
		}
	}
	b, err := openBucket(ctx, st, c)
	if err != nil {
		return err
	}
	defer b.Close()
	objs, more, err := b.List(ctx, prefix, true, 1_000_000)
	if err != nil {
		return err
	}
	if more {
		return out.Usage("more than a million objects under %q; use a narrower --prefix", prefix)
	}
	cutoff := time.Now().Add(-age)
	var keys []string
	var total int64
	for _, o := range objs {
		if o.Dir || (age > 0 && !o.Modified.Before(cutoff)) {
			continue
		}
		keys = append(keys, o.Key)
		total += o.Size
	}
	sort.Strings(keys)
	res := map[string]any{"conn": c.Name, "prefix": prefix, "count": len(keys), "bytes": total}
	if len(keys) > limit {
		res["keys"] = keys[:limit]
		out.P.Print("storage.rm", res, out.Errf(out.ExitConflict, "TOO_MANY", fmt.Sprintf("narrow --prefix or --older-than, or raise --limit above %d after checking the list", len(keys)),
			"%d objects match, more than --limit %d", len(keys), limit))
		return exitCode(out.ExitConflict)
	}
	if g.dryRun {
		res["would_delete"], res["dry_run"] = keys, true
		out.P.Print("storage.rm", res, nil)
		return nil
	}
	done, err := removeKeys(ctx, b, keys)
	rec["conns"], rec["deleted"] = []string{c.Name}, len(done)
	audit(st, "storage.rm", nil, "", err == nil, rec)
	if err != nil {
		return err
	}
	res["deleted"] = done
	out.P.Print("storage.rm", res, nil)
	return nil
}

func storageCatCmd() *cobra.Command {
	var head, tail int
	var maxBytes int64
	c := &cobra.Command{
		Use:   "cat CONN KEY",
		Short: "Show an object's content (text); --head/--tail N lines, at most --max-bytes",
		Example: `  komando storage cat backups logs/app-2026-11-02.log --tail 50
  komando storage cat config prod/app.env`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStorage(cmd.Context(), "storage.cat", args[0], driver.Verdict{}, map[string]any{"key": args[1]},
				func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					w := &capWriter{max: maxBytes}
					if tail > 0 {
						w.max = 64 << 20 // the end needs the whole object; keep it bounded
					}
					if _, err := s.Get(ctx, args[1], w); err != nil && !w.capped { // stopping at the limit is not a failure
						return nil, err
					}
					text, truncated := w.buf.String(), w.capped
					if !utf8.ValidString(text) {
						return nil, out.Errf(out.ExitConflict, "NOT_TEXT", "download it with `komando storage download`", "%s is not text", args[1])
					}
					lines := strings.SplitAfter(text, "\n")
					if len(lines) > 0 && lines[len(lines)-1] == "" {
						lines = lines[:len(lines)-1]
					}
					switch {
					case head > 0 && len(lines) > head:
						lines, truncated = lines[:head], true
					case tail > 0 && len(lines) > tail:
						lines = lines[len(lines)-tail:]
					}
					return catData{Conn: c.Name, Key: args[1], Content: strings.Join(lines, ""), Truncated: truncated}, nil
				})
		},
	}
	c.Flags().IntVar(&head, "head", 0, "only the first N lines")
	c.Flags().IntVar(&tail, "tail", 0, "only the last N lines")
	c.Flags().Int64Var(&maxBytes, "max-bytes", 1<<20, "read at most this much (default 1 MiB)")
	return c
}

type catData struct {
	Conn      string `json:"conn"`
	Key       string `json:"key"`
	Content   string `json:"content"`
	Truncated bool   `json:"truncated,omitempty"`
}

func (d catData) Text() string { return d.Content }

var errCapped = errors.New("komando: read limit reached")

// capWriter keeps the first max bytes and then stops the download.
type capWriter struct {
	buf    bytes.Buffer
	max    int64
	capped bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	room := w.max - int64(w.buf.Len())
	if int64(len(p)) > room {
		w.buf.Write(p[:max(room, 0)])
		w.capped = true
		return int(max(room, 0)), errCapped
	}
	return w.buf.Write(p)
}

func storageLinkCmd() *cobra.Command {
	var expires time.Duration
	c := &cobra.Command{
		Use:     "link CONN KEY",
		Aliases: []string{"presign", "share"},
		Short:   "Make a temporary download link that works without a login",
		Long: `Prints a URL anyone can use to download KEY until it expires (default 1 hour,
at most 7 days). Treat it like a password while it is valid. Sharing from a
protected conn needs --yes. The link itself is not stored in the audit log.`,
		Example: `  komando storage link backups reports/q3.pdf --expires 24h`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if expires <= 0 || expires > 7*24*time.Hour {
				return out.Usage("--expires must be between 1s and 168h (7 days)")
			}
			// a link opens data to anyone who has it: treat it like a change
			return withStorage(cmd.Context(), "storage.link", args[0], driver.Verdict{Risk: driver.RiskWrite}, map[string]any{"key": args[1], "expires": expires.String()},
				func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					u, err := s.Link(ctx, args[1], expires)
					if err != nil {
						return nil, err
					}
					return linkData{Conn: c.Name, Key: args[1], URL: u.String(), ExpiresAt: time.Now().Add(expires).UTC()}, nil
				})
		},
	}
	c.Flags().DurationVar(&expires, "expires", time.Hour, "how long the link works (max 168h)")
	return c
}

type linkData struct {
	Conn      string    `json:"conn"`
	Key       string    `json:"key"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (d linkData) Text() string { return d.URL + "\n" }

// storageDownload saves one object to a new local file (never overwriting).
func storageDownload(ctx context.Context, name, conn, key, to string) error {
	if err := guardSensitiveCopy(key); err != nil {
		return err
	}
	dest := to
	if dest == "" {
		dest = path.Base(key)
	}
	if _, err := os.Stat(dest); err == nil {
		return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another name with --to; downloads never overwrite", "%s already exists", dest)
	}
	return withStorage(ctx, name, conn, driver.Verdict{}, map[string]any{"key": key, "file": dest},
		func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
			var n int64
			err := writeAtomic(dest, func(tmp string) error {
				f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_TRUNC, 0o600)
				if err != nil {
					return err
				}
				defer f.Close()
				if n, err = s.Get(ctx, key, f); err != nil {
					return err
				}
				return f.Sync()
			})
			if err != nil {
				return nil, err
			}
			return transferData{Conn: c.Name, File: dest, Bytes: n, RunsOn: "local"}, nil
		})
}

// storageUpload uploads one local file; key defaults to the file's name.
func storageUpload(ctx context.Context, name, conn, file, key string) error {
	if key == "" {
		key = filepath.Base(file)
	}
	fi, err := os.Stat(file)
	if err != nil || fi.IsDir() {
		return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "give a regular file (folders are not uploaded)", "cannot upload %s", file)
	}
	return withStorage(ctx, name, conn, driver.Verdict{Risk: driver.RiskWrite}, map[string]any{"key": key, "file": file, "bytes": fi.Size()},
		func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
			replaced, err := s.Exists(ctx, key)
			if err != nil {
				return nil, err
			}
			f, err := os.Open(file)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			ct := mime.TypeByExtension(filepath.Ext(file))
			if err := s.Put(ctx, key, f, fi.Size(), ct); err != nil {
				return nil, err
			}
			return map[string]any{"conn": c.Name, "key": key, "bytes": fi.Size(), "replaced": replaced}, nil
		})
}
