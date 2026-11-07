package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
// never overwrite a local file unless --overwrite.

func storageCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "storage",
		Aliases: []string{"s3"},
		Short:   "Files in buckets and on file servers (S3, MinIO, R2, FTPS, SFTP): list, download, upload, share",
		Long: `Work with a storage conn (see ` + "`komando conn`" + `): an S3-compatible bucket, or a
folder on an FTPS, FTP or SFTP server. Keys are relative to the folder in the
conn URL; a key ending in / is a folder. ls, cat and download only read.
upload changes files and link shares one (S3 only; protected conns need --yes
for both); rm deletes, so it also needs --allow-dangerous. Downloads never
overwrite a local file unless --overwrite, and uploads to file servers go to
a temporary name first, so a failed upload leaves nothing half written.`,
	}
	c.AddCommand(storageLsCmd(), storageCatCmd(), storageDownloadCmd(), storageUploadCmd(), storageRmCmd(), storageLinkCmd())
	return c
}

type storageFn func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error)

// withStorage resolves the conn, applies the seatbelts for v, runs fn and
// audits the action. Dry runs of changes stop before contacting the server.
func withStorage(ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn storageFn) error {
	return withStoragePreview(ctx, name, connExpr, v, rec, fn, nil)
}

// withStoragePreview is withStorage with a dry-run preview: for a change,
// --dry-run runs preview (which only reads) instead of fn.
func withStoragePreview(ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn, preview storageFn) error {
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
			if preview == nil {
				audit(st, name, nil, "", true, rec)
				out.P.Print(name, map[string]any{"conn": c.Name, "risk": v.Risk.String(), "dry_run": true, "note": "nothing sent: the change would be allowed"}, nil)
				return nil
			}
			fn = preview
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
	if data != nil {
		out.P.Print(name, data, nil)
	}
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
		if profile := awsProfile(c); profile != "" {
			// SSO, an assumed role or temporary keys, as the aws CLI has them now
			cr, cerr := awsCredentials(ctx, profile)
			if cerr != nil {
				a.Close()
				return nil, cerr
			}
			b, err = storex.OpenS3Creds(a.Target, cr.AccessKeyID, cr.SecretAccessKey, cr.SessionToken, a.Dial, dbTimeout())
		} else {
			b, err = storex.OpenS3(a.Target, a.Password, a.Dial, dbTimeout())
		}
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

// LinkAt passes through to the bucket inside (S3 only), so storage link
// --endpoint works for conns reached through --via, the case it is for.
func (c closeBoth) LinkAt(ctx context.Context, key string, expires time.Duration, endpoint *url.URL) (*url.URL, error) {
	at, ok := c.Bucket.(interface {
		LinkAt(context.Context, string, time.Duration, *url.URL) (*url.URL, error)
	})
	if !ok {
		return nil, out.Usage("--endpoint works for S3 conns only")
	}
	return at.LinkAt(ctx, key, expires, endpoint)
}

type objectList struct {
	Conn    string          `json:"conn"`
	Prefix  string          `json:"prefix"`
	Objects []storex.Object `json:"objects"`
	Count   int             `json:"count"`
	More    bool            `json:"more"`
}

func (l objectList) Text() string {
	var b strings.Builder
	b.WriteString(objectTable(l.Objects))
	if l.More {
		fmt.Fprintf(&b, "(first %d; more exist: narrow the prefix or raise --limit)\n", l.Count)
	}
	return b.String()
}

// objectTable lists objects one per line: size, time, key.
func objectTable(objs []storex.Object) string {
	if len(objs) == 0 {
		return ""
	}
	rows := make([][]string, len(objs))
	for i, o := range objs {
		if o.Dir {
			rows[i] = []string{"DIR", "", o.Key}
			continue
		}
		rows[i] = []string{humanBytes(o.Size), o.Modified.Format("2006-01-02 15:04"), o.Key}
	}
	return dataTable([]string{"size", "modified", "key"}, rows)
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
					if len(objs) == 0 && strings.Trim(prefix, "/") != "" {
						// a bucket has no folders, only keys: nothing under the
						// prefix is what a missing folder is on a file server
						return nil, storex.FolderNotFound(prefix)
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
	var recursive, overwrite bool
	c := &cobra.Command{
		Use:     "download CONN KEY",
		Aliases: []string{"get"},
		Short:   "Download an object (or a folder with -r) to this computer; same as `komando download CONN KEY`",
		Long: `Saves KEY to a file named like the key in the current folder, or to --to:
a file name, a folder (existing, or ending in /), or - for stdout (text
output only). An existing file is never replaced unless --overwrite. With -r,
KEY is a folder and everything under it is downloaded; files already here
are kept unless --overwrite. --dry-run shows what would be saved where.`,
		Example: `  komando storage download backups db/app-2026-11-02.sql.gz
  komando storage download backups reports/q3.pdf --to ~/Downloads/
  komando storage download backups logs/app.log --to - -o text | less
  komando storage download backups reports/ -r --to ./reports`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if recursive {
				if to == "-" {
					return out.Usage("-r saves a folder; --to - (stdout) takes one file")
				}
				dest := to
				if dest == "" {
					dest = path.Base(strings.TrimSuffix(args[1], "/"))
				}
				return syncDown(cmd.Context(), "storage.download", args[0], args[1], dest, syncOpts{onlyNew: !overwrite})
			}
			return storageDownloadTo(cmd.Context(), "storage.download", args[0], args[1], to, overwrite)
		},
	}
	c.Flags().StringVar(&to, "to", "", "file or folder to save to, or - for stdout (default: the key's file name here)")
	c.Flags().BoolVarP(&recursive, "recursive", "r", false, "download every object under the KEY folder")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace files that already exist on this computer")
	return c
}

func storageUploadCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "upload CONN FILE [KEY]",
		Aliases: []string{"put"},
		Short:   "Same as `komando upload CONN FILE [KEY]`",
		Long: `Uploads FILE to KEY. Without KEY it keeps the file's name; a KEY ending in /
is a folder, so the file keeps its name inside it. An existing object is
replaced (the result says so); --dry-run checks the key and says whether it
would replace one.`,
		Example: `  komando storage upload backups prod-2026-11-02.sql.gz
  komando storage upload backups ./report.pdf reports/2026/
  komando storage upload backups ./report.pdf reports/2026/q3.pdf --dry-run`,
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
				if err := storex.CheckKey(k); err != nil {
					return err
				}
			}
			var age time.Duration
			if olderThan != "" {
				var err error
				if age, err = parseAge(olderThan, "--older-than"); err != nil {
					return err
				}
			}
			rec := map[string]any{"keys": keys, "prefix": prefix, "older_than": olderThan}
			if prefix != "" {
				// list first, even in a dry run: the answer is the list
				return storageRmPrefix(cmd.Context(), args[0], folderKey(prefix), age, limit, rec)
			}
			return withStoragePreview(cmd.Context(), "storage.rm", args[0], driver.DataDelete(), rec,
				func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					done, err := removeKeys(ctx, s, keys)
					rec["deleted"] = done
					if err != nil {
						return nil, err
					}
					return map[string]any{"conn": c.Name, "deleted": done}, nil
				},
				func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					p := rmPlan{Conn: c.Name, DryRun: true, WouldDelete: []string{}, Missing: []string{}}
					for _, k := range keys {
						o, err := s.Stat(ctx, k)
						if err != nil {
							if toErr(err).Exit == out.ExitNotFound {
								p.Missing = append(p.Missing, k)
								continue
							}
							return nil, err
						}
						p.objs = append(p.objs, o)
						p.WouldDelete = append(p.WouldDelete, k)
						p.Bytes += o.Size
					}
					p.Count = len(p.WouldDelete)
					return p, nil
				})
		},
	}
	c.Flags().StringVar(&prefix, "prefix", "", "remove everything under this folder (e.g. daily/; / for the whole conn)")
	c.Flags().StringVar(&olderThan, "older-than", "", "with --prefix: only objects older than this (30d, 12h, 90m)")
	c.Flags().IntVarP(&limit, "limit", "n", 1000, "refuse when more than this many objects would be removed")
	return c
}

// parseAge reads a positive duration with days (30d) as well as Go units
// (12h, 90m); flag names the flag in the error.
func parseAge(s, flag string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(d); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, nil
	}
	return 0, out.Usage("%s takes a positive duration like 30d, 12h or 90m (got %q)", flag, s)
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

// rmPlan is what rm removes (or, in a dry run or over --limit, would).
type rmPlan struct {
	Conn        string   `json:"conn"`
	Prefix      string   `json:"prefix,omitempty"`
	Count       int      `json:"count"`
	Bytes       int64    `json:"bytes"`
	Keys        []string `json:"keys,omitempty"`         // over --limit: the first ones
	WouldDelete []string `json:"would_delete,omitempty"` // dry run
	Missing     []string `json:"missing,omitempty"`      // dry run of exact keys: not there
	Deleted     []string `json:"deleted,omitempty"`
	DryRun      bool     `json:"dry_run,omitempty"`
	objs        []storex.Object
}

func (p rmPlan) Text() string {
	var b strings.Builder
	switch {
	case p.Deleted != nil:
		fmt.Fprintf(&b, "deleted %d object%s (%s)\n", len(p.Deleted), plural(len(p.Deleted)), humanBytes(p.Bytes))
		return b.String()
	case p.DryRun:
		b.WriteString(objectTable(p.objs))
		for _, k := range p.Missing {
			fmt.Fprintf(&b, "%s does not exist\n", k)
		}
		fmt.Fprintf(&b, "would delete %d object%s (%s)\n", p.Count, plural(p.Count), humanBytes(p.Bytes))
	default: // over --limit
		b.WriteString(objectTable(p.objs))
		fmt.Fprintf(&b, "(the first %d of %d objects, %s in all)\n", len(p.objs), p.Count, humanBytes(p.Bytes))
	}
	return b.String()
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
	if err := guardConns(st, []*store.Conn{c}, driver.DataDelete()); err != nil {
		return err // under --dry-run this only records the stop
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
	p := rmPlan{Conn: c.Name, Prefix: prefix}
	for _, o := range objs {
		if o.Dir || (age > 0 && !o.Modified.Before(cutoff)) {
			continue
		}
		p.objs = append(p.objs, o)
		p.Bytes += o.Size
	}
	sort.Slice(p.objs, func(i, j int) bool { return p.objs[i].Key < p.objs[j].Key })
	keys := make([]string, len(p.objs))
	for i, o := range p.objs {
		keys[i] = o.Key
	}
	p.Count = len(keys)
	if len(keys) > limit {
		p.Keys, p.objs = keys[:limit], p.objs[:limit]
		out.P.Print("storage.rm", p, out.Errf(out.ExitConflict, "TOO_MANY", fmt.Sprintf("narrow --prefix or --older-than, or raise --limit above %d after checking the list", len(keys)),
			"%d objects match, more than --limit %d", len(keys), limit))
		return exitCode(out.ExitConflict)
	}
	if g.dryRun {
		p.WouldDelete, p.DryRun = keys, true
		out.P.Print("storage.rm", p, nil)
		return nil
	}
	done, err := removeKeys(ctx, b, keys)
	rec["conns"], rec["deleted"] = []string{c.Name}, len(done)
	audit(st, "storage.rm", nil, "", err == nil, rec)
	if err != nil {
		return err
	}
	p.Deleted = done
	out.P.Print("storage.rm", p, nil)
	return nil
}

func storageCatCmd() *cobra.Command {
	var head, tail int
	var maxBytes int64
	c := &cobra.Command{
		Use:   "cat CONN KEY",
		Short: "Show an object's content (text); --head or --tail N lines, at most --max-bytes",
		Example: `  komando storage cat backups logs/app-2026-11-02.log --tail 50
  komando storage cat config prod/app.env`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fl := cmd.Flags()
			if fl.Changed("head") && fl.Changed("tail") {
				return out.Usage("pick one of --head and --tail")
			}
			if fl.Changed("head") && head < 1 || fl.Changed("tail") && tail < 1 {
				return out.Usage("--head and --tail take a number of lines (1 or more)")
			}
			if maxBytes < 1 {
				return out.Usage("--max-bytes must be 1 or more")
			}
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
					if w.capped {
						text = strings.ToValidUTF8(text[:len(text)-incompleteRune(text)], "") // cut inside a character
					}
					if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
						return nil, out.Errf(out.ExitUsage, "NOT_TEXT", "download it with `komando storage download CONN KEY`", "%s is not text", args[1])
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
					if w.capped && out.P.Format == "text" {
						fmt.Fprintf(os.Stderr, "(truncated at %s; raise --max-bytes or download it)\n", humanBytes(w.max))
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

// incompleteRune is how many bytes at the end of s start a character that
// was cut off.
func incompleteRune(s string) int {
	for n := 1; n <= 3 && n <= len(s); n++ {
		if utf8.RuneStart(s[len(s)-n]) {
			if !utf8.FullRuneInString(s[len(s)-n:]) {
				return n
			}
			return 0
		}
	}
	return 0
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
	var endpoint string
	c := &cobra.Command{
		Use:     "link CONN KEY",
		Aliases: []string{"presign", "share"},
		Short:   "Make a temporary download link that works without a login",
		Long: `Prints a URL anyone can use to download KEY until it expires (default 1 hour,
at most 7 days). Treat it like a password while it is valid. Sharing from a
protected conn needs --yes. The link itself is not stored in the audit log.
The link names the storage address in the conn URL: when komando reaches it
through --via, only people who can reach that address can use the link.
--endpoint signs the link for the address they use instead (S3 only).`,
		Example: `  komando storage link backups reports/q3.pdf --expires 24h
  komando storage link backups reports/q3.pdf --endpoint https://files.example.com`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if expires <= 0 || expires > 7*24*time.Hour {
				return out.Usage("--expires must be between 1s and 168h (7 days)")
			}
			var pub *url.URL
			if endpoint != "" {
				u, err := url.Parse(endpoint)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.Trim(u.Path, "/") != "" {
					return out.Usage("--endpoint must be http(s)://HOST[:PORT], e.g. https://files.example.com")
				}
				pub = u
			}
			// a link opens data to anyone who has it: treat it like a change
			return withStorage(cmd.Context(), "storage.link", args[0], driver.Verdict{Risk: driver.RiskWrite}, map[string]any{"key": args[1], "expires": expires.String()},
				func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					var u *url.URL
					var err error
					if pub != nil {
						at, ok := s.(interface {
							LinkAt(context.Context, string, time.Duration, *url.URL) (*url.URL, error)
						})
						if !ok {
							return nil, out.Usage("--endpoint works for S3 conns; %s cannot make links", c.Name)
						}
						u, err = at.LinkAt(ctx, args[1], expires, pub)
					} else {
						u, err = s.Link(ctx, args[1], expires)
					}
					if err != nil {
						return nil, err
					}
					via := c.Via
					if pub != nil {
						via = "" // signed for the address people use
					}
					d := linkData{Conn: c.Name, Key: args[1], URL: u.String(), ExpiresAt: time.Now().Add(expires).UTC(), Warning: linkWarning(u, via)}
					if d.Warning != "" && out.P.Format == "text" {
						fmt.Fprintln(os.Stderr, "warning: "+d.Warning)
					}
					return d, nil
				})
		},
	}
	c.Flags().DurationVar(&expires, "expires", time.Hour, "how long the link works (max 168h)")
	c.Flags().StringVar(&endpoint, "endpoint", "", "sign the link for this address, e.g. https://files.example.com (when komando reaches the storage through --via)")
	return c
}

// linkWarning says when a link points at an address only komando's --via
// path can reach.
func linkWarning(u *url.URL, via string) string {
	if via == "" {
		return ""
	}
	return fmt.Sprintf("the link points at %s, which komando reaches through %s; people outside that network cannot open it (sign it for their address with --endpoint https://PUBLIC-NAME)", u.Host, via)
}

type linkData struct {
	Conn      string    `json:"conn"`
	Key       string    `json:"key"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
	Warning   string    `json:"warning,omitempty"`
}

func (d linkData) Text() string { return d.URL + "\n" }

// uploadKey is where FILE goes: KEY, the file's name inside KEY when KEY
// is a folder (ends in /), or the file's name.
func uploadKey(file, key string) string {
	if key == "" || strings.HasSuffix(key, "/") {
		return key + filepath.Base(file)
	}
	return key
}

type uploadData struct {
	Conn     string `json:"conn"`
	File     string `json:"file"`
	Key      string `json:"key"`
	Bytes    int64  `json:"bytes"`
	Replaced bool   `json:"replaced"`
	DryRun   bool   `json:"dry_run,omitempty"`
}

func (d uploadData) Text() string {
	if d.DryRun {
		return fmt.Sprintf("would upload %s -> %s (%s, replaces existing: %s)\n", d.File, d.Key, humanBytes(d.Bytes), yesNo(d.Replaced))
	}
	s := fmt.Sprintf("uploaded %s -> %s (%s)", d.File, d.Key, humanBytes(d.Bytes))
	if d.Replaced {
		s += ", replaced the old object"
	}
	return s + "\n"
}

// storageUpload uploads one local file; key defaults to the file's name.
func storageUpload(ctx context.Context, name, conn, file, key string) error {
	key = uploadKey(file, key)
	if err := storex.CheckKey(key); err != nil {
		return err
	}
	fi, err := os.Stat(file)
	if err != nil || fi.IsDir() {
		return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "give a regular file (folders go with -r: `komando upload CONN DIR KEY -r`)", "cannot upload %s", file)
	}
	if err := guardLocalRead(file); err != nil {
		return err
	}
	data := func(c *store.Conn, s storex.Bucket, ctx context.Context) (uploadData, error) {
		replaced, err := s.Exists(ctx, key)
		return uploadData{Conn: c.Name, File: file, Key: key, Bytes: fi.Size(), Replaced: replaced}, err
	}
	return withStoragePreview(ctx, name, conn, driver.Verdict{Risk: driver.RiskWrite}, map[string]any{"key": key, "file": file, "bytes": fi.Size()},
		func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
			d, err := data(c, s, ctx)
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
			return d, nil
		},
		func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
			d, err := data(c, s, ctx)
			d.DryRun = true
			return d, err
		})
}
