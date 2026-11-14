package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// Old versions in a bucket that keeps them (S3 versioning): storage list
// --all-versions shows them, storage rm --all-versions removes a key with
// every version, so it is really gone.

// versioned is s as a bucket that keeps versions, or NOT_SUPPORTED.
func versioned(c *store.Conn, s storex.Bucket) (storex.Versioned, error) {
	for {
		w, ok := s.(interface{ Unwrap() storex.Bucket })
		if !ok {
			break
		}
		s = w.Unwrap() // the bucket inside closeBoth and the like
	}
	v, ok := s.(storex.Versioned)
	if !ok {
		return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED", "leave out --all-versions: only S3 buckets (and S3-compatible stores) keep versions komando can see",
			"%s is a %s conn; --all-versions is for S3 buckets", c.Name, c.Kind)
	}
	return v, nil
}

type versionList struct {
	Conn     string                 `json:"conn"`
	Prefix   string                 `json:"prefix,omitempty"`
	Count    int                    `json:"count"`
	More     bool                   `json:"more,omitempty"`
	Versions []storex.ObjectVersion `json:"versions"`
}

func (l versionList) Text() string {
	if len(l.Versions) == 0 {
		return "no objects under " + cmpPrefix(l.Prefix) + "\n"
	}
	rows := make([][]string, 0, len(l.Versions))
	for _, v := range l.Versions {
		state := ""
		switch {
		case v.DeleteMarker && v.Latest:
			state = "deleted (marker)"
		case v.DeleteMarker:
			state = "delete marker"
		case v.Latest:
			state = "current"
		default:
			state = "old"
		}
		size := humanBytes(v.Size)
		if v.DeleteMarker {
			size = "-"
		}
		rows = append(rows, []string{v.Key, v.VersionID, state, size, timeCell(v.Modified)})
	}
	s := textTable([]string{"key", "version", "state", "size", "modified"}, rows)
	if l.More {
		s += fmt.Sprintf("(the first %d; raise --limit)\n", len(l.Versions))
	}
	return s
}

func cmpPrefix(p string) string {
	if p == "" {
		return "the conn"
	}
	return p
}

// listVersions is storage list --all-versions.
func listVersions(cl *call, ctx context.Context, c *store.Conn, s storex.Bucket, prefix string, limit int) (any, error) {
	v, err := versioned(c, s)
	if err != nil {
		return nil, err
	}
	vs, more, err := v.Versions(ctx, prefix, limit)
	if err != nil {
		return nil, err
	}
	if more {
		cl.out.CutNoted()
	}
	return versionList{Conn: c.Name, Prefix: prefix, Count: len(vs), More: more, Versions: vs}, nil
}

// keyVersions are every version and delete marker of the exact keys.
func keyVersions(ctx context.Context, v storex.Versioned, keys []string) ([]storex.ObjectVersion, error) {
	var all []storex.ObjectVersion
	for _, k := range keys {
		vs, _, err := v.Versions(ctx, k, 0)
		if err != nil {
			return nil, err
		}
		for _, x := range vs {
			if x.Key == k { // the prefix also lists k.bak, k/...
				all = append(all, x)
			}
		}
	}
	return all, nil
}

// rmVersionsData is storage rm --all-versions: each version it took (or
// in a dry run would take).
type rmVersionsData struct {
	Conn     string                 `json:"conn"`
	DryRun   bool                   `json:"dry_run,omitempty"`
	Count    int                    `json:"count"`
	Versions []storex.ObjectVersion `json:"versions"`
}

func (d rmVersionsData) Text() string {
	verb := "deleted"
	if d.DryRun {
		verb = "would delete"
	}
	keys := map[string]bool{}
	for _, v := range d.Versions {
		keys[v.Key] = true
	}
	return fmt.Sprintf("%s %d version%s of %s\n", verb, d.Count, plural(d.Count), strings.Join(mapKeys(keys), ", "))
}

// storageRmVersions is storage rm --all-versions: a preview under
// --dry-run, else the same confirmation as rm, then every version goes.
func storageRmVersions(cl *call, ctx context.Context, conn string, keys []string, rec map[string]any) error {
	rec["all_versions"] = true
	return withStoragePreview(cl, ctx, "storage.rm", conn, driver.DataDelete(), rec,
		func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
			return rmAllVersions(ctx, c, s, keys, false)
		},
		func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
			return rmAllVersions(ctx, c, s, keys, true)
		})
}

// rmAllVersions removes every version of the keys (dry: lists them).
func rmAllVersions(ctx context.Context, c *store.Conn, s storex.Bucket, keys []string, dry bool) (any, error) {
	v, err := versioned(c, s)
	if err != nil {
		return nil, err
	}
	vs, err := keyVersions(ctx, v, keys)
	if err != nil {
		return nil, err
	}
	d := rmVersionsData{Conn: c.Name, DryRun: dry, Count: len(vs), Versions: vs}
	if d.Versions == nil {
		d.Versions = []storex.ObjectVersion{}
	}
	if dry {
		return d, nil
	}
	for i, x := range vs {
		if err := v.RemoveVersion(ctx, x.Key, x.VersionID); err != nil {
			e := toErr(err)
			e.Message += fmt.Sprintf(" (already deleted: %d of %d versions)", i, len(vs))
			return nil, e
		}
	}
	return d, nil
}
