package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"slices"
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

// Storage commands work with every storage conn kind (S3, GCS, Azure Blob,
// WebDAV, FTP, FTPS, SFTP and SMB) through one interface. Like files on a
// server: ls and download read, upload and rm change (protected conns need
// --yes), and downloads never overwrite a local file unless --overwrite.

func storageCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "storage",
		Aliases: []string{"s3"},
		Short:   "Buckets (S3, GCS, Azure) and file servers: browse, copy, remove",
		Long: `List, copy and share files in a bucket or on a file server. Add one with
` + "`komando storage add`" + `.

It works with an S3-compatible, Google Cloud Storage or Azure Blob bucket,
or a folder on a WebDAV, FTPS, FTP or SFTP server or an SMB share (Windows,
Samba, Azure Files). Keys are relative to the folder in the storage URL; a
key ending in / is a folder. ls, cat and download only read. upload changes
files and link shares one (S3, Google Cloud and Azure; on production
storage both ask first); rm deletes, so it also needs --allow-dangerous.
Downloads never overwrite a local file unless --overwrite, and uploads to
file servers go to a temporary name first, so a failed upload leaves
nothing half written.

The storage itself: komando storage add, komando test CONN, komando conn
edit CONN, komando conn rm CONN. komando list kind:storage lists them.`,
		Example: `  komando storage add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --ask-password
  komando storage list backups 2026/
  komando download backups 2026/app.sql.gz --to ./
  komando storage rm backups --prefix daily/ --older-than 30d --dry-run`,
	}
	add := connAddCmdFor("storage")
	add.Example += `
  komando storage add backups 's3://my-bucket/db?region=eu-west-1' --option aws_profile=prod   # AWS SSO or a role
  komando storage add minio 's3://AKIAEXAMPLE@media?endpoint=https://minio.internal:9000' --via bastion --ask-password
  komando storage add media gs://my-bucket/site   # logs in like gcloud
  komando storage add files azblob://mystorageacct@uploads/2026 --password-ref secret:files-key
  komando storage add site 'sftp://deploy@files.example.com/uploads'`
	c.AddCommand(add, storageLsCmd(), storageCatCmd(), storageDownloadCmd(), storageUploadCmd(), storageRmCmd(), storageLinkCmd())
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
		err = namedHint(err, c.Name)
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

// namedHint puts the conn's name into the next command a storage error
// names (the drivers know no conn: they say NAME or CONN), so a person or
// an agent can run the hint as it is.
func namedHint(err error, conn string) error {
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Hint == "" {
		return err
	}
	h := oe.Hint
	for _, cmd := range []string{"conn test ", "conn show ", "conn edit ", "storage list ", "download ", "upload "} {
		for _, word := range []string{"NAME", "CONN"} {
			h = strings.ReplaceAll(h, "komando "+cmd+word, "komando "+cmd+conn)
		}
	}
	if h == oe.Hint {
		return err
	}
	e := *oe
	e.Hint = h
	return &e
}

// openBucket connects to a storage conn of any kind (a variable so tests
// can give a bucket in memory).
var openBucket = func(ctx context.Context, st *store.State, c *store.Conn) (storex.Bucket, error) {
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
	case "webdav":
		b, err = storex.OpenWebDAV(a.Target, a.Password, a.Dial, dbTimeout())
	case "gcs":
		b, err = storex.OpenGCS(ctx, a.Target, a.Password, a.Dial, dbTimeout())
	case "azblob":
		b, err = storex.OpenAzure(a.Target, a.Password, a.Dial, dbTimeout())
	case "smb":
		b, err = storex.OpenSMB(ctx, a.Target, a.Password, a.Dial, dbTimeout())
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

// TemporaryKeys passes through to the bucket inside (S3 only).
func (c closeBoth) TemporaryKeys() bool { return temporaryKeys(c.Bucket) }

// temporaryKeys: the bucket logs in with temporary keys, so its links end
// when the keys do.
func temporaryKeys(b storex.Bucket) bool {
	t, ok := b.(interface{ TemporaryKeys() bool })
	return ok && t.TemporaryKeys()
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
	if len(l.Objects) == 0 && l.Prefix != "" {
		return "nothing under " + l.Prefix + " in " + l.Conn + "\n"
	}
	if len(l.Objects) == 0 {
		return l.Conn + " is empty: `komando upload " + l.Conn + " FILE` adds a file\n"
	}
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
		Use:   "list CONN [PREFIX]",
		Short: "List the objects and folders of a storage conn",
		Example: `  komando storage list backups
  komando storage list backups db/2026-11/ --recursive`,
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
					if folder := strings.TrimPrefix(prefix, "/") + "/"; !recursive && folder != "/" && !strings.HasSuffix(prefix, "/") &&
						slices.ContainsFunc(objs, func(o storex.Object) bool { return o.Dir && o.Key == folder }) {
						// a bucket lists the folder itself (and db.sql) for "db";
						// a file server lists what is in the folder db: do that
						// everywhere when the prefix names a folder
						prefix = folder
						if objs, more, err = s.List(ctx, prefix, false, limit); err != nil {
							return nil, err
						}
					}
					if len(objs) == 0 && strings.Trim(prefix, "/") != "" {
						// a bucket has no folders, only keys: nothing under the
						// prefix is what a missing folder is on a file server
						return nil, storex.FolderNotFound(prefix)
					}
					if more {
						out.P.CutNoted()
					}
					return objectList{Conn: c.Name, Prefix: prefix, Objects: objs, Count: len(objs), More: more}, nil
				})
		},
	}
	c.Flags().BoolVarP(&recursive, "recursive", "r", false, "include everything below the prefix, not just one level")
	c.Flags().IntVarP(&limit, "limit", "n", 1000, "the most entries to show")
	withID(c, "storage.ls") // `ls` before: a permanent synonym
	return c
}

func storageCatCmd() *cobra.Command {
	var head, tail int
	var maxBytes int64
	c := &cobra.Command{
		Use:   "cat CONN OBJECT",
		Short: "Show the text of an object",
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
						return nil, out.Errf(out.ExitUsage, "NOT_TEXT", "download it with `komando storage download CONN OBJECT`", "%s is not text", args[1])
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
	maxBytes = 1 << 20
	c.Flags().Var(&bytesFlag{n: &maxBytes}, "max-bytes", "read at most this many bytes, e.g. 4MiB (1048576 is 1 MiB)")
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
		Use:     "link CONN OBJECT",
		Aliases: []string{"presign", "share"},
		Short:   "Make a temporary download link that works without a login",
		Long: `Prints a URL anyone can use to download KEY until it expires (default 1 hour,
at most 7 days). Treat it like a password while it is valid. Sharing from a
protected conn needs --yes. The link itself is not stored in the audit log.
The link names the storage address in the conn URL: when komando reaches it
through --via, only people who can reach that address can use the link.
--endpoint signs the link for the address they use instead (S3 only).`,
		Example: `  komando storage link backups reports/q3.pdf --expires 24h
  komando storage link backups reports/q3.pdf --expires 7d
  komando storage link backups reports/q3.pdf --endpoint https://files.example.com`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if expires <= 0 || expires > 7*24*time.Hour {
				return out.Usage("--expires must be between 1s and 7d (168h)")
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
					if temporaryKeys(s) {
						w := "the link is signed with temporary AWS keys (profile " + awsProfile(c) + "), so it stops working when they expire, which can be before expires_at; for a link that lasts, give the conn an access key of its own (--password-ref)"
						d.Warning = strings.TrimPrefix(d.Warning+"; "+w, "; ")
					}
					if d.Warning != "" && out.P.Format == "text" {
						fmt.Fprintln(os.Stderr, "warning: "+d.Warning)
					}
					return d, nil
				})
		},
	}
	expires = time.Hour
	c.Flags().Var(&durFlag{d: &expires, positive: true, name: "expires"}, "expires", "how long the link works, e.g. 30m, 24h or 7d (at most 7d)")
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
	if err := hiddenInLocal(file); err != nil {
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
