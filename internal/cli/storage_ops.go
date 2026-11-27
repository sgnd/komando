package cli

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

// storage s3 object create, mv and chmod: tidy up a bucket or a file server. Each is
// a change like upload: --dry-run first, a protected conn asks, and every
// run is in the audit log.

// copyKinds are the storage kinds that have no rename: mv copies, checks
// the copy and only then deletes the original.
var copyKinds = map[string]bool{"s3": true, "gcs": true, "azblob": true}

// storageKindWords name each storage kind in messages.
var storageKindWords = map[string]string{"s3": "S3", "gcs": "Google Cloud Storage", "azblob": "Azure Blob",
	"webdav": "WebDAV", "ftp": "FTP", "ftps": "FTPS", "smb": "SMB", "sftp": "SFTP"}

// storageKind is the kind of the conn connExpr names (s3, sftp, ...),
// read from its URL without contacting it.
func storageKind(cl *call, connExpr string) (*store.Conn, string, error) {
	st, err := loadState()
	if err != nil {
		return nil, "", err
	}
	c, err := singleConn(cl, st, connExpr, "storage")
	if err != nil {
		return nil, "", err
	}
	t, err := driver.Parse(c.URL)
	if err != nil {
		return nil, "", err
	}
	return c, t.Kind.Name, nil
}

// storagePath is a PATH, SRC or DST argument, checked before anything is
// contacted: it may not be empty or leave the conn's folder.
func storagePath(p string) (string, error) {
	r := strings.Trim(p, "/")
	if err := storex.CheckKey(r); err != nil {
		return "", err
	}
	if r == "." || path.Clean(r) != r {
		return "", out.Usage("write %q without . or // in it", p)
	}
	return r, nil
}

func storageMkdirCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mkdir CONN PATH",
		Short: "Create a folder in a storage conn, with any missing parents",
		Long: `Makes the folder PATH and any missing folders above it. A folder that is
already there is fine (created: false); a file with that name stops it
(FILE_EXISTS).

S3, Google Cloud Storage and Azure Blob have no real folders, only names
with / in them: there mkdir stores an empty folder marker (PATH/), as their
web consoles do, so the folder shows in storage s3 object list before any file is in
it.`,
		Example: `  komando storage s3 object create backups reports/2026 --dry-run
  komando storage s3 object create backups reports/2026`,
		Args: cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			p, err := storagePath(args[1])
			if err != nil {
				return err
			}
			return withStoragePreview(cl, cmd.Context(), "storage.mkdir", args[0], driver.Verdict{Risk: driver.RiskWrite}, map[string]any{"path": p},
				func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					existed, err := s.Mkdir(ctx, p)
					if err != nil {
						return nil, err
					}
					return mkdirData{Conn: c.Name, Path: p + "/", Created: !existed}, nil
				},
				func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					o, found, err := s.Lookup(ctx, p)
					if err != nil {
						return nil, err
					}
					if found && !o.Dir {
						return nil, out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another name; `komando storage s3 object list NAME [PREFIX]` shows what is there",
							"a file named %q is already there", p)
					}
					return mkdirData{Conn: c.Name, Path: p + "/", Created: !found, DryRun: true}, nil
				})
		}),
	}
}

type mkdirData struct {
	Conn    string `json:"conn"`
	Path    string `json:"path"`
	Created bool   `json:"created"`
	DryRun  bool   `json:"dry_run,omitempty"`
}

func (d mkdirData) Text() string {
	switch {
	case !d.Created && d.DryRun:
		return d.Path + " is already there; nothing to do\n"
	case !d.Created:
		return d.Path + " is already there\n"
	case d.DryRun:
		return "would make the folder " + d.Path + "\n"
	}
	return "made the folder " + d.Path + "\n"
}

func storageMvCmd() *cobra.Command {
	var overwrite bool
	c := &cobra.Command{
		Use:   "mv CONN SRC DST",
		Short: "Move or rename a file or folder inside a storage conn",
		Long: `Moves SRC to DST inside one conn. A DST ending in / is a folder: SRC moves
into it and keeps its name. Missing folders above DST are made. A file
already at DST stops the move (FILE_EXISTS) unless --overwrite; a folder
at DST is never replaced.

On a file server (SFTP, FTP, FTPS, WebDAV, SMB) mv is one rename on the
server, and moves folders too.

S3, Google Cloud Storage and Azure Blob cannot rename: mv copies the object
on the server, checks that the copy has the same size and checksum, and
only then deletes the original (method: copy_then_delete). If the check
fails, the original stays and the copy is deleted (MOVE_FAILED). There
mv moves one object at a time, not a folder. In a bucket that keeps old
versions, the original's old versions stay.`,
		Example: `  komando storage s3 object move backups db/old.sql.gz archive/ --dry-run
  komando storage s3 object move backups db/old.sql.gz archive/
  komando storage s3 object move backups reports/draft.pdf reports/q3.pdf --overwrite`,
		Args: cobra.ExactArgs(3),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			src, err := storagePath(args[1])
			if err != nil {
				return err
			}
			dstArg := args[2]
			if strings.HasSuffix(dstArg, "/") {
				dstArg += path.Base(src) // into the folder, with its own name
			}
			dst, err := storagePath(dstArg)
			if err != nil {
				return err
			}
			if src == dst {
				return out.Usage("SRC and DST are the same (%q)", src)
			}
			if err := guardSensitiveRename(cl, src, dst); err != nil {
				return err
			}
			_, kind, err := storageKind(cl, args[0])
			if err != nil {
				return err
			}
			method := "rename"
			if copyKinds[kind] {
				method = "copy_then_delete"
			}
			rec := map[string]any{"src": src, "dst": dst, "overwrite": overwrite, "method": method}
			run := func(dry bool) storageFn {
				return func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					m, err := s.Move(ctx, src, dst, storex.MoveOpts{Overwrite: overwrite, DryRun: dry})
					if err != nil {
						return nil, err
					}
					rec["replaced"] = m.Replaced
					return mvData{Conn: c.Name, Src: src, Dst: dst, Folder: m.Folder, Replaced: m.Replaced,
						Method: method, SizeBytes: m.Size, DryRun: dry}, nil
				}
			}
			return withStoragePreview(cl, cmd.Context(), "storage.mv", args[0], driver.Verdict{Risk: driver.RiskWrite}, rec, run(false), run(true))
		}),
	}
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace a file already at DST (never a folder)")
	return c
}

// guardSensitiveRename stops an AI agent from giving a file that is secret
// by its name (.env, a private key, a key store) a name that is not: under
// the new name it would pass the stops for secret files (storage download,
// object read, cp). A move that keeps a secret name is an ordinary move.
func guardSensitiveRename(cl *call, src, dst string) error {
	if !cl.isAgent() || !sensitiveName(src) || sensitiveName(dst) {
		return nil
	}
	return out.Errf(out.ExitPolicy, "SENSITIVE_FILE",
		fmt.Sprintf("move it with its name kept (`komando storage s3 object move NAME %s FOLDER/`), or ask the user to run the command in their own terminal", argQ(src)),
		"%s holds secrets; komando does not give it another kind of name for an AI agent", src).NoFlag()
}

type mvData struct {
	Conn      string `json:"conn"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Folder    bool   `json:"folder,omitempty"`
	Replaced  bool   `json:"replaced"`
	Method    string `json:"method"` // rename, or copy_then_delete (S3, Google Cloud Storage, Azure Blob)
	SizeBytes int64  `json:"size_bytes"`
	DryRun    bool   `json:"dry_run,omitempty"`
}

func (d mvData) Text() string {
	what := term.HumanBytes(d.SizeBytes)
	if d.Folder {
		what = "folder"
	}
	how := ""
	if d.Method == "copy_then_delete" {
		how = ", copied and checked, then the original deleted"
		if d.DryRun {
			how = ", by a copy that is checked before the original is deleted"
		}
	}
	if d.DryRun {
		return fmt.Sprintf("would move %s -> %s (%s%s; replaces a file: %s)\n", d.Src, d.Dst, what, how, yesNo(d.Replaced))
	}
	s := fmt.Sprintf("moved %s -> %s (%s%s)", d.Src, d.Dst, what, how)
	if d.Replaced {
		s += ", replaced the old file"
	}
	return s + "\n"
}

func storageChmodCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "chmod CONN MODE PATH",
		Short: "Change the mode of a file or folder on an SFTP conn",
		Long: `Sets the Unix mode of PATH (a file or a folder) on an SFTP server, like
chmod. MODE is in digits: 0644, 640, 0750, or 2775 with the setgid bit; the
result says the old mode too. Only SFTP servers have modes: other kinds of
storage stop with STORAGE_UNSUPPORTED before anything is contacted.`,
		Example: `  komando storage sftp object move backups config/app.yml --mode 0640 --dry-run
  komando storage sftp object move backups config/app.yml --mode 0640
  komando storage sftp object move backups uploads --mode 0750`,
		Args: cobra.ExactArgs(3),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			mode, err := parseStorageMode(args[1])
			if err != nil {
				if _, swapped := parseStorageMode(args[2]); swapped == nil {
					return out.Usage("%q is not a mode in digits like 0644 (komando storage sftp object move NAME PATH --mode 0640)", args[1])
				}
				return err
			}
			p, err := storagePath(args[2])
			if err != nil {
				return err
			}
			c, kind, err := storageKind(cl, args[0])
			if err != nil {
				return err
			}
			if kind != "sftp" {
				return out.Errf(out.ExitUsage, "STORAGE_UNSUPPORTED", "chmod works on SFTP conns; `komando list kind:storage` lists yours",
					"%s is %s storage, which has no file modes", c.Name, storageKindWords[kind])
			}
			rec := map[string]any{"path": p, "mode": modeDigits(mode)}
			run := func(dry bool) storageFn {
				return func(ctx context.Context, c *store.Conn, s storex.Bucket) (any, error) {
					m, ok := storex.Inner(s).(storex.Modes)
					if !ok {
						return nil, out.Errf(out.ExitUsage, "STORAGE_UNSUPPORTED", "chmod works on SFTP conns; `komando list kind:storage` lists yours",
							"%s has no file modes", c.Name)
					}
					old, err := m.Mode(ctx, p)
					if err != nil {
						return nil, err
					}
					d := chmodData{Conn: c.Name, Path: p, Mode: modeDigits(mode), OldMode: modeDigits(old), DryRun: dry}
					rec["old_mode"] = d.OldMode
					if old.IsDir() {
						d.Path += "/"
					}
					if !dry {
						if err := m.Chmod(ctx, p, mode); err != nil {
							return nil, err
						}
					}
					return d, nil
				}
			}
			return withStoragePreview(cl, cmd.Context(), "storage.chmod", args[0], driver.Verdict{Risk: driver.RiskWrite}, rec, run(false), run(true))
		}),
	}
}

// parseStorageMode reads a mode in digits (644, 0640, 2775) as a file
// mode, with the setuid, setgid and sticky bits.
func parseStorageMode(s string) (fs.FileMode, error) {
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil || len(s) < 3 || len(s) > 4 {
		return 0, out.Usage("%q is not a mode in digits like 0644 or 0750", s)
	}
	m := fs.FileMode(n & 0o777)
	for bit, flag := range map[uint64]fs.FileMode{0o4000: fs.ModeSetuid, 0o2000: fs.ModeSetgid, 0o1000: fs.ModeSticky} {
		if n&bit != 0 {
			m |= flag
		}
	}
	return m, nil
}

// modeDigits is m as chmod's four digits (0644, 2775).
func modeDigits(m fs.FileMode) string {
	n := uint32(m.Perm())
	for flag, bit := range map[fs.FileMode]uint32{fs.ModeSetuid: 0o4000, fs.ModeSetgid: 0o2000, fs.ModeSticky: 0o1000} {
		if m&flag != 0 {
			n |= bit
		}
	}
	return fmt.Sprintf("%04o", n)
}

type chmodData struct {
	Conn    string `json:"conn"`
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	OldMode string `json:"old_mode"`
	DryRun  bool   `json:"dry_run,omitempty"`
}

func (d chmodData) Text() string {
	if d.DryRun {
		return fmt.Sprintf("would set mode %s on %s (now %s)\n", d.Mode, d.Path, d.OldMode)
	}
	return fmt.Sprintf("mode %s on %s (was %s)\n", d.Mode, d.Path, d.OldMode)
}
