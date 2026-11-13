package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
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
}

func (d downloadData) Text() string {
	if d.DryRun {
		s := fmt.Sprintf("would save %s to %s (%s)", d.Key, d.File, humanBytes(d.Bytes))
		if d.Replaces {
			s += ", replacing the file there"
		}
		return s + "\n"
	}
	s := fmt.Sprintf("%s: %s (%s)\n", d.Conn, d.File, humanBytes(d.Bytes))
	if d.Masked {
		s += "saved with secret values shown as [hidden], as fs cat shows them\n"
	}
	return s
}

// storageDownloadTo saves one object to a local file, - (stdout), or a
// folder; an existing file is replaced only with overwrite.
func storageDownloadTo(ctx context.Context, name, conn, key, to string, overwrite bool) error {
	if err := guardSensitiveCopy(key); err != nil {
		return err
	}
	if strings.HasSuffix(key, "/") {
		return out.Usage("%q is a folder; add -r to download everything in it", key)
	}
	if err := storex.CheckKey(key); err != nil {
		return err
	}
	toStdout := to == "-"
	if toStdout && out.P.Format != "text" {
		return out.Usage("--to - writes the file itself to stdout, where JSON output goes too; add -o text, or give a file name")
	}
	dest := downloadDest(to, key)
	exists := false
	if !toStdout {
		if fi, err := os.Stat(dest); err == nil {
			if fi.IsDir() {
				return out.Errf(out.ExitConflict, "FILE_EXISTS", "give a file name with --to", "%s is a folder", dest)
			}
			if !overwrite {
				return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another name with --to, or add --overwrite to replace it", "%s already exists", dest)
			}
			exists = true
		}
	}
	return withStorage(ctx, name, conn, driver.Verdict{}, map[string]any{"key": key, "file": dest},
		func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
			if g.dryRun { // a download changes this computer: check, write nothing
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
			mask := out.P.Mask && !revealOK()
			if toStdout && mask {
				// an AI agent reads it here: shown as fs cat shows text
				var b bytes.Buffer
				n, err := s.Get(ctx, key, &limitWriter{w: &b, n: hiddenScanMax})
				if err != nil {
					return nil, err
				}
				if n > hiddenScanMax {
					return nil, out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "save it to a file with --to FILE",
						"%s is larger than %s, the most komando shows an AI agent on stdout", key, humanBytes(hiddenScanMax))
				}
				text := b.String()
				if bytes.IndexByte(b.Bytes(), 0) < 0 {
					text = out.P.Redact(text)
				}
				_, err = io.WriteString(out.P.W, text)
				return nil, err
			}
			if toStdout {
				_, err := s.Get(ctx, key, out.P.W)
				return nil, err
			}
			var n int64
			masked := false
			fill := func(tmp string) error {
				f, err := os.OpenFile(tmp, os.O_RDWR|os.O_TRUNC, 0o600)
				if err != nil {
					return err
				}
				defer f.Close()
				if !mask {
					if n, err = s.Get(ctx, key, f); err != nil {
						return err
					}
					return f.Sync()
				}
				if n, masked, err = getMasked(ctx, s, key, f); err != nil {
					return err
				}
				return f.Sync()
			}
			var err error
			if exists {
				err = writeReplacing(dest, fill)
			} else {
				err = writeAtomic(dest, fill)
			}
			if err != nil {
				return nil, err
			}
			return downloadData{Conn: c.Name, Key: key, File: dest, Bytes: n, Replaces: exists, Masked: masked, RunsOn: "local"}, nil
		})
}

// writeReplacing is writeAtomic for --overwrite: the new file replaces the
// old one only once it is complete.
func writeReplacing(dest string, fill func(tmp string) error) error {
	dir, err := os.MkdirTemp(filepath.Dir(dest), ".komando-*")
	if err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "check that the folder exists and is writable", "%v", err)
	}
	defer os.RemoveAll(dir)
	tmp := filepath.Join(dir, "data")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	if err := fill(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "check that the folder is writable and has free space", "%v", err)
	}
	return nil
}

// getMasked saves object key into f for an AI agent, masked before it
// reaches the disk (fetchMasked).
func getMasked(ctx context.Context, s storex.Bucket, key string, f *os.File) (int64, bool, error) {
	pr, pw := io.Pipe()
	defer pr.Close()
	go func() {
		_, err := s.Get(ctx, key, pw)
		pw.CloseWithError(err)
	}()
	return fetchMasked(ctx, pr, f, io.Discard, nil)
}
