package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
	"github.com/sgnd/komando/internal/tmpclean"
)

// downloadDest is where a download lands: to as given, inside it when it
// is a folder (existing, or ending in /), or the key's name here.
func downloadDest(to, key string) string {
	base := path.Base(key)
	switch {
	case to == "":
		return base
	case strings.HasSuffix(to, "/") || strings.HasSuffix(to, string(filepath.Separator)):
		return filepath.Join(to, base)
	}
	if fi, err := os.Stat(to); err == nil && fi.IsDir() {
		return filepath.Join(to, base)
	}
	return to
}

type downloadData struct {
	Conn     string `json:"conn"`
	Key      string `json:"key"`
	File     string `json:"file"`
	Bytes    int64  `json:"bytes"`
	Replaces bool   `json:"replaces,omitempty"`
	Masked   bool   `json:"masked,omitempty"` // saved with secret values shown as [hidden] (AI agents)
	DryRun   bool   `json:"dry_run,omitempty"`
	RunsOn   string `json:"runs_on"`
	// --continue: the file's sha256, checked against the object, and the
	// bytes that were already here and stayed
	SHA256        string `json:"sha256,omitempty"`
	ContinuedFrom int64  `json:"continued_from_bytes,omitempty"`
}

func (d downloadData) Text() string {
	if d.DryRun {
		s := fmt.Sprintf("would save %s to %s (%s)", d.Key, d.File, term.HumanBytes(d.Bytes))
		if d.Replaces {
			s += ", replacing the file there"
		}
		return s + "\n"
	}
	s := fmt.Sprintf("%s: %s (%s)\n", d.Conn, d.File, term.HumanBytes(d.Bytes))
	if d.ContinuedFrom > 0 {
		s += fmt.Sprintf("went on after the %s already here\n", term.HumanBytes(d.ContinuedFrom))
	}
	if d.Masked {
		s += "saved with secret values shown as [hidden], as fs cat shows them\n"
	}
	return s
}

// storageDownloadTo saves one object to a local file, - (stdout), or a
// folder; an existing file is replaced only with overwrite, and continued
// only with resume (--continue).
func storageDownloadTo(cl *call, ctx context.Context, name, conn, key, to string, overwrite, resume bool) error {
	if err := guardDownload(cl, key, to); err != nil {
		return err
	}
	if strings.HasSuffix(key, "/") {
		return out.Errf(out.ExitUsage, "IS_A_DIRECTORY", "add -r to download everything in it: `komando storage download CONN "+key+" -r`", "%q is a folder", key)
	}
	if err := storex.CheckKey(key); err != nil {
		return err
	}
	toStdout := to == "-"
	dest := downloadDest(to, key)
	exists := false
	if !toStdout {
		if fi, err := os.Stat(dest); err == nil {
			if fi.IsDir() {
				return out.Errf(out.ExitConflict, "FILE_EXISTS", "give a file name with --to", "%s is a folder", dest)
			}
			if !overwrite && !resume {
				return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another name with --to, or add --overwrite to replace it", "%s already exists", dest)
			}
			exists = !resume
		}
	}
	return withStorage(cl, ctx, name, conn, driver.Verdict{}, map[string]any{"key": key, "file": dest},
		func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
			if cl.dryRun() { // a download changes this computer: check, write nothing
				o, err := s.Stat(ctx, key)
				if err != nil {
					return nil, err
				}
				file := dest
				if toStdout {
					file = "stdout"
				}
				return downloadData{Conn: c.Name, Key: key, File: file, Bytes: o.Size, Replaces: exists, DryRun: true, RunsOn: "local"}, nil
			}
			mask := cl.out.Mask && !cl.revealOK()
			if toStdout {
				raw := takeStdout(cl)
				r, err := streamTo(cl, ctx, raw, func(w io.Writer) (int64, error) { return s.Get(ctx, key, w) })
				if err != nil {
					return nil, err
				}
				return streamData{Conn: c.Name, Key: key, To: "stdout", Bytes: r.bytes, SHA256: r.sum, Masked: r.masked}, nil
			}
			if resume {
				return continueObject(cl, ctx, c.Name, s, key, dest)
			}
			pp := objectProgress(ctx, s, key)
			var n int64
			masked := false
			fill := func(tmp string) error {
				f, err := os.OpenFile(tmp, os.O_RDWR|os.O_TRUNC, 0o600)
				if err != nil {
					return err
				}
				defer f.Close()
				if !mask {
					var w io.Writer = f
					if pw := pp.writer(); pw != nil {
						w = io.MultiWriter(f, pw)
					}
					if n, err = s.Get(ctx, key, w); err != nil {
						return err
					}
					return f.Sync()
				}
				if n, masked, err = getMasked(cl, ctx, s, key, f, pp.writer()); err != nil {
					return err
				}
				return f.Sync()
			}
			var err error
			if exists {
				err = writeReplacing(cl, dest, fill)
			} else {
				err = writeAtomic(cl, dest, fill)
			}
			if err != nil {
				return nil, err
			}
			pp.fileDone()
			return downloadData{Conn: c.Name, Key: key, File: dest, Bytes: n, Replaces: exists, Masked: masked, RunsOn: "local"}, nil
		})
}

// objectProgress starts --progress's count for one object, with its size
// as the total: one more look at the object, made only with --progress.
func objectProgress(ctx context.Context, s storex.Bucket, key string) *progressPart {
	pp := progressFrom(ctx)
	if pp == nil {
		return nil
	}
	if o, err := s.Stat(ctx, key); err == nil {
		pp.total(1, o.Size)
	} else {
		pp.unknown()
	}
	pp.start(key)
	return pp
}

// writeReplacing is writeAtomic for --overwrite: the new file replaces the
// old one only once it is complete.
func writeReplacing(cl *call, dest string, fill func(tmp string) error) error {
	if err := guardLocalWrite(cl, dest); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(dest), ".komando-*")
	if err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "check that the folder exists and is writable", "%v", err)
	}
	defer os.RemoveAll(dir)
	defer tmpclean.Add(dir)()
	tmp := filepath.Join(dir, "data")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	if err := fill(tmp); err != nil {
		return err
	}
	if err := guardLocalWrite(cl, dest); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "check that the folder is writable and has free space", "%v", err)
	}
	return nil
}

// getMasked saves object key into f for an AI agent, masked before it
// reaches the disk (fetchMasked). watch, when not nil, sees every byte.
func getMasked(cl *call, ctx context.Context, s storex.Bucket, key string, f *os.File, watch io.Writer) (int64, bool, error) {
	// getReader: when fetchMasked stops early, Close waits for the download
	// to end, so the next call on an FTP conn reads its own reply (C122)
	r := getReader(ctx, func(ctx context.Context, w io.Writer) error {
		_, err := s.Get(ctx, key, w)
		return err
	})
	defer r.Close()
	return fetchMasked(cl, ctx, r, f, io.Discard, watch)
}

// continueObject is storage download --continue: one object into dest,
// going on from the part already there.
func continueObject(cl *call, ctx context.Context, conn string, s storex.Bucket, key, dest string) (any, error) {
	if err := mkdirLocal(cl, filepath.Dir(dest)); err != nil {
		var refused *out.Error
		if errors.As(err, &refused) {
			return nil, err
		}
		return nil, out.Errf(out.ExitError, "FILE_ERROR", "check that the folder is writable", "%v", err)
	}
	r, err := continueDownload(cl, ctx, bucketEnd{conn: conn, b: s, key: key}, dest, 0o644, key)
	if err != nil {
		return nil, err
	}
	return downloadData{Conn: conn, Key: key, File: dest, Bytes: r.bytes, RunsOn: "local", SHA256: r.sum, ContinuedFrom: r.from}, nil
}
