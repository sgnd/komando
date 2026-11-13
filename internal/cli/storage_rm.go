package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// storage rm: exact keys, or everything under a folder (--prefix).

func storageRmCmd() *cobra.Command {
	var prefix, olderThan string
	var limit int
	var allVersions bool
	c := &cobra.Command{
		Use:   "rm CONN [OBJECT...]",
		Short: "Delete objects by name or prefix",
		Long: `Without --prefix, rm takes exact keys (no patterns). With --prefix it removes
every object under that folder, or with --older-than only the ones older
than that (30d, 12h): the usual cleanup of old backups. --dry-run lists them
first; --max-remove (default 1000) refuses to go on when more would be removed.

In an S3 bucket with versioning, rm leaves the old versions behind (and a
delete marker): --all-versions removes every version of the keys too, so
they are really gone. ` + "`storage list CONN PREFIX --all-versions`" + ` shows them.`,
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
				return out.Errf(out.ExitUsage, "USAGE",
					fmt.Sprintf("for example: komando storage rm %s KEY, or komando storage rm %s --prefix FOLDER/ --dry-run (komando storage list %s shows the keys). To take %s out of komando's list, not its files: komando conn rm %s", args[0], args[0], args[0], args[0], args[0]),
					"give exact keys, or --prefix FOLDER/")
			}
			if prefix != "" && len(keys) > 0 {
				return out.Usage("give keys or --prefix, not both")
			}
			if allVersions && prefix != "" {
				return out.Usage("--all-versions takes exact keys; list a folder's versions first with `komando storage list %s %s --all-versions`", args[0], prefix)
			}
			for _, k := range keys {
				if strings.HasSuffix(k, "/") || strings.ContainsAny(k, "*?") {
					return out.Usage("%q looks like a folder or pattern; use --prefix for folders (see `komando storage list`)", k)
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
			askTypes(keys, "files in "+args[0])
			if prefix != "" {
				// list first, even in a dry run: the answer is the list
				return storageRmPrefix(cmd.Context(), args[0], folderKey(prefix), age, limit, rec)
			}
			if allVersions {
				rec["all_versions"] = true
				return withStoragePreview(cmd.Context(), "storage.rm", args[0], driver.DataDelete(), rec,
					func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
						return rmAllVersions(ctx, c, s, keys, false)
					},
					func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
						return rmAllVersions(ctx, c, s, keys, true)
					})
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
	c.Flags().StringVar(&prefix, "prefix", "", "remove everything under this folder (like daily/; / for the whole conn)")
	spanText(c.Flags(), &olderThan, "older-than", "", true, "with --prefix: only objects older than this (like 30d, 12h, 90m)")
	// a safety cap, not a list's --limit (S-5.1)
	c.Flags().IntVar(&limit, "max-remove", 1000, "refuse when more than this many objects would be removed")
	c.Flags().BoolVar(&allVersions, "all-versions", false, "S3: also remove every old version and delete marker of the keys, so they are really gone")
	return c
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

// rmPlan is what rm removes (or, in a dry run or over --max-remove, would).
type rmPlan struct {
	Conn        string   `json:"conn"`
	Prefix      string   `json:"prefix,omitempty"`
	Count       int      `json:"count"`
	Bytes       int64    `json:"bytes"`
	Keys        []string `json:"keys,omitempty"`         // over --max-remove: the first ones
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
	default: // over --max-remove
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
	// a person at the terminal sees what goes before typing the name; an
	// agent, a script or --allow-dangerous are stopped (or let through)
	// before anything is listed, as for every destructive command
	person := !g.dryRun && !g.allowDangerous && interactive()
	if !person {
		if err := guardConns(st, []*store.Conn{c}, driver.DataDelete()); err != nil {
			return err // under --dry-run this only records the stop
		}
	}
	b, err := openBucket(ctx, st, c)
	if err != nil {
		return namedHint(err, c.Name)
	}
	defer b.Close()
	objs, more, err := b.List(ctx, prefix, true, 1_000_000)
	if err != nil {
		return namedHint(err, c.Name)
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
		out.P.Print("storage.rm", p, out.Errf(out.ExitConflict, "TOO_MANY", fmt.Sprintf("narrow --prefix or --older-than, or raise --max-remove above %d after checking the list", len(keys)),
			"%d objects match, more than --max-remove %d", len(keys), limit))
		return exitCode(out.ExitConflict)
	}
	if g.dryRun {
		p.WouldDelete, p.DryRun = keys, true
		out.P.Print("storage.rm", p, nil)
		return nil
	}
	if person && len(keys) > 0 {
		fmt.Fprint(os.Stderr, rmPreview(p))
		v := driver.DataDelete()
		v.Reasons = []string{fmt.Sprintf("deletes %d object%s (%s) %s for good, unless the bucket keeps old versions",
			len(keys), plural(len(keys)), humanBytes(p.Bytes), p.where())}
		askTypes(keys, "objects "+p.where())
		if err := guardConns(st, []*store.Conn{c}, v); err != nil {
			return err
		}
	}
	done, err := removeKeys(ctx, b, keys)
	rec["conns"], rec["deleted"] = []string{c.Name}, len(done)
	audit(st, "storage.rm", nil, "", err == nil, rec)
	if err != nil {
		return namedHint(err, c.Name)
	}
	p.Deleted = done
	out.P.Print("storage.rm", p, nil)
	return nil
}

// rmPreview is what a person sees before typing the name: the first
// objects and how many there are in all.
func rmPreview(p rmPlan) string {
	const show = 20
	objs := p.objs
	if len(objs) > show {
		objs = objs[:show]
	}
	s := objectTable(objs)
	if more := len(p.objs) - len(objs); more > 0 {
		s += fmt.Sprintf("... and %d more\n", more)
	}
	return s + fmt.Sprintf("%d object%s (%s) %s\n", p.Count, plural(p.Count), humanBytes(p.Bytes), p.where())
}

// where names the folder rm --prefix empties: "under daily/ in backups",
// or "in all of backups".
func (p rmPlan) where() string {
	if p.Prefix == "" {
		return "in all of " + p.Conn
	}
	return "under " + p.Prefix + " in " + p.Conn
}
