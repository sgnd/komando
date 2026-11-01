package cli

import (
	"context"
	"fmt"
	"mime"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// Storage commands work with S3-compatible buckets. Like files on a server:
// ls and get read, put and rm change (protected conns need --yes), and
// downloads never overwrite a local file.

func storageCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "storage",
		Aliases: []string{"s3"},
		Short:   "Object storage (S3, MinIO, R2, Wasabi, ...): list, download, upload, share",
		Long: `Work with a storage conn (see ` + "`komando conn`" + `). Keys are relative to the
folder in the conn URL. ls and download only read. upload changes the bucket
and link shares an object (protected conns need --yes for both); rm deletes,
so it also needs --allow-dangerous. Downloads never overwrite a local file.`,
	}
	c.AddCommand(storageLsCmd(), storageDownloadCmd(), storageUploadCmd(), storageRmCmd(), storageLinkCmd())
	return c
}

// withStorage resolves the conn, applies the seatbelts for v, runs fn and
// audits the action. Dry runs of changes stop before contacting the server.
func withStorage(ctx context.Context, name, connExpr string, v driver.Verdict, rec map[string]any, fn func(ctx context.Context, c *store.Conn, s *storex.Store) (any, error)) error {
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
		if err := guardConns([]*store.Conn{c}, v); err != nil {
			return fail(err)
		}
		if g.dryRun {
			audit(st, name, nil, "", true, rec)
			out.P.Print(name, map[string]any{"conn": c.Name, "risk": v.Risk.String(), "dry_run": true, "note": "nothing sent: the change would be allowed"}, nil)
			return nil
		}
	}
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	s, err := storex.Open(a.Target, a.Password, a.Dial, dbTimeout())
	if err != nil {
		return fail(err)
	}
	if g.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.timeout)
		defer cancel()
	}
	data, err := fn(ctx, c, s)
	if err != nil {
		return fail(err)
	}
	audit(st, name, nil, "", true, rec)
	out.P.Print(name, data, nil)
	return nil
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
				func(ctx context.Context, c *store.Conn, s *storex.Store) (any, error) {
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
		Short:   "Download an object to a file on this computer (never overwrites)",
		Example: `  komando storage download backups db/app-2026-11-02.sql.gz
  komando storage download backups reports/q3.pdf --to ~/Downloads/q3.pdf`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dest := to
			if dest == "" {
				dest = path.Base(args[1])
			}
			if _, err := os.Stat(dest); err == nil {
				return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another name with --to; downloads never overwrite", "%s already exists", dest)
			}
			return withStorage(cmd.Context(), "storage.download", args[0], driver.Verdict{}, map[string]any{"key": args[1], "file": dest},
				func(ctx context.Context, c *store.Conn, s *storex.Store) (any, error) {
					var n int64
					err := writeAtomic(dest, func(tmp string) error {
						f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_TRUNC, 0o600)
						if err != nil {
							return err
						}
						defer f.Close()
						if n, err = s.Get(ctx, args[1], f); err != nil {
							return err
						}
						return f.Sync()
					})
					if err != nil {
						return nil, err
					}
					return transferData{Conn: c.Name, File: dest, Bytes: n, RunsOn: "local"}, nil
				})
		},
	}
	c.Flags().StringVar(&to, "to", "", "file to create (default: the key's file name in the current folder)")
	return c
}

func storageUploadCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "upload CONN FILE [KEY]",
		Aliases: []string{"put"},
		Short:   "Upload a file (replaces an object with the same key)",
		Example: `  komando storage upload backups prod-2026-11-02.sql.gz
  komando storage upload backups ./report.pdf reports/2026/q3.pdf`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			file := args[1]
			key := filepath.Base(file)
			if len(args) == 3 {
				key = args[2]
			}
			fi, err := os.Stat(file)
			if err != nil || fi.IsDir() {
				return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "give a regular file (folders are not uploaded)", "cannot upload %s", file)
			}
			return withStorage(cmd.Context(), "storage.upload", args[0], driver.Verdict{Risk: driver.RiskWrite}, map[string]any{"key": key, "file": file, "bytes": fi.Size()},
				func(ctx context.Context, c *store.Conn, s *storex.Store) (any, error) {
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
		},
	}
	return c
}

func storageRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm CONN KEY...",
		Aliases: []string{"delete", "del", "remove"},
		Short:   "Delete objects by exact key (no patterns or folders; needs --allow-dangerous)",
		Example: `  komando storage rm backups tmp/old.sql.gz --allow-dangerous`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			keys := args[1:]
			for _, k := range keys {
				if strings.HasSuffix(k, "/") || strings.ContainsAny(k, "*?") {
					return out.Usage("%q looks like a folder or pattern; rm takes exact keys (see `komando storage ls`)", k)
				}
			}
			rec := map[string]any{"keys": keys}
			return withStorage(cmd.Context(), "storage.rm", args[0], driver.DataDelete(), rec,
				func(ctx context.Context, c *store.Conn, s *storex.Store) (any, error) {
					var done []string
					for _, k := range keys {
						if err := s.Remove(ctx, k); err != nil {
							rec["deleted"] = done
							e := toErr(err)
							if len(done) > 0 {
								e.Message += fmt.Sprintf(" (already deleted: %s)", strings.Join(done, ", "))
							}
							return nil, e
						}
						done = append(done, k)
					}
					return map[string]any{"conn": c.Name, "deleted": done}, nil
				})
		},
	}
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
				func(ctx context.Context, c *store.Conn, s *storex.Store) (any, error) {
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
