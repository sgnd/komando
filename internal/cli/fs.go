package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func fsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "fs",
		Short: "Remote filesystem: ls, stat, cat, write, replace (agent-safe edits), rm, mkdir, mv, chmod",
		Long: `Structured file operations over SFTP. Use --sudo to operate on root-owned
files (reads via 'sudo cat', writes via a temp file + 'sudo install').

'fs replace' is the safest way for an agent to edit config: it fails unless
the old text matches exactly once (or --all), and can keep a .bak backup.`,
	}
	c.AddCommand(fsLsCmd(), fsStatCmd(), fsCatCmd(), fsWriteCmd(), fsReplaceCmd(), fsRmCmd(), fsMkdirCmd(), fsMvCmd(), fsChmodCmd())
	return c
}

func sftpClient(c *sshx.Client) (*sftp.Client, error) {
	s, err := sftp.NewClient(c.Client)
	if err != nil {
		return nil, out.Errf(out.ExitConnect, "SFTP_UNAVAILABLE", "enable the sftp subsystem in sshd_config", "sftp: %v", err)
	}
	return s, nil
}

// oneHost resolves target, dials it and runs fn with both ssh and sftp.
func oneHost(ctx context.Context, target string, fn func(st *store.State, c *sshx.Client, sc *sftp.Client) (any, error)) (any, *store.State, *store.Host, error) {
	st, err := loadState()
	if err != nil {
		return nil, nil, nil, err
	}
	h, err := singleHost(st, target)
	if err != nil {
		return nil, st, nil, err
	}
	var res any
	err = withClient(ctx, st, h, func(c *sshx.Client) error {
		sc, err := sftpClient(c)
		if err != nil {
			return err
		}
		defer sc.Close()
		res, err = fn(st, c, sc)
		return err
	})
	return res, st, h, err
}

func fsErr(p string, err error) error {
	return fsErrHint(p, err, "retry with --sudo")
}

// fsErrHint is fsErr for commands without --sudo: permHint says what to do
// about a permission problem instead.
func fsErrHint(p string, err error, permHint string) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return out.Errf(out.ExitNotFound, "PATH_NOT_FOUND", "list the folder with `komando fs ls TARGET "+path.Dir(p)+"`", "%s: no such file or directory", p)
	case errors.Is(err, os.ErrPermission):
		return out.Errf(out.ExitError, "PERMISSION_DENIED", permHint, "%s: permission denied", p)
	}
	return err
}

type fileInfo struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Type    string    `json:"type"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mod_time"`
	UID     uint32    `json:"uid,omitempty"`
	GID     uint32    `json:"gid,omitempty"`
	Link    string    `json:"link_target,omitempty"`
}

func toInfo(dir string, fi os.FileInfo) fileInfo {
	t := "file"
	switch {
	case fi.IsDir():
		t = "dir"
	case fi.Mode()&os.ModeSymlink != 0:
		t = "symlink"
	case !fi.Mode().IsRegular():
		t = "other"
	}
	inf := fileInfo{Name: fi.Name(), Path: path.Join(dir, fi.Name()), Type: t, Size: fi.Size(), Mode: fmt.Sprintf("%04o", fi.Mode().Perm()), ModTime: fi.ModTime().UTC()}
	if s, ok := fi.Sys().(*sftp.FileStat); ok {
		inf.UID, inf.GID = s.UID, s.GID
	}
	return inf
}

func fsLsCmd() *cobra.Command {
	var all bool
	var recursive bool
	var maxEntries int
	c := &cobra.Command{
		Use:   "ls TARGET [PATH]",
		Short: "List a remote directory (default: the login user's home)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			arg := ""
			if len(args) == 2 {
				arg = args[1]
			}
			res, _, _, err := oneHost(cmd.Context(), args[0], func(_ *store.State, _ *sshx.Client, sc *sftp.Client) (any, error) {
				dir := expandRemote(sc, arg)
				permHint := "fs ls reads as the SSH user; list it as root with `komando exec " + args[0] + " --sudo -- ls -la " + sshx.Q(dir) + "`"
				r := lsResult{Path: dir, Entries: []fileInfo{}, recursive: recursive}
				if fi, err := sc.Stat(dir); err != nil {
					return nil, fsErrHint(dir, err, permHint)
				} else if !fi.IsDir() {
					inf := toInfo(path.Dir(dir), fi)
					r.Entries = append(r.Entries, inf) // like ls FILE
					r.Count = 1
					return r, nil
				}
				if recursive {
					w := sc.Walk(dir)
					for w.Step() {
						if w.Err() != nil {
							continue
						}
						if w.Path() == dir {
							continue
						}
						if !all && strings.HasPrefix(path.Base(w.Path()), ".") {
							if w.Stat().IsDir() {
								w.SkipDir()
							}
							continue
						}
						if len(r.Entries) >= maxEntries {
							r.Truncated = true
							break
						}
						r.Entries = append(r.Entries, toInfo(path.Dir(w.Path()), w.Stat()))
					}
				} else {
					fis, err := sc.ReadDir(dir)
					if err != nil {
						return nil, fsErrHint(dir, err, permHint)
					}
					for _, fi := range fis {
						if !all && strings.HasPrefix(fi.Name(), ".") {
							continue
						}
						if len(r.Entries) >= maxEntries {
							r.Truncated = true
							break
						}
						r.Entries = append(r.Entries, toInfo(dir, fi))
					}
				}
				for i := range r.Entries {
					if r.Entries[i].Type == "symlink" {
						r.Entries[i].Link, _ = sc.ReadLink(r.Entries[i].Path)
					}
				}
				r.Count = len(r.Entries)
				return r, nil
			})
			if err != nil {
				return err
			}
			out.P.Print("fs.ls", res, nil)
			return nil
		},
	}
	c.Flags().BoolVarP(&all, "all", "a", false, "include dotfiles")
	c.Flags().BoolVarP(&recursive, "recursive", "r", false, "walk recursively")
	c.Flags().IntVar(&maxEntries, "max", 1000, "max entries returned")
	return c
}

func fsStatCmd() *cobra.Command {
	var hash bool
	c := &cobra.Command{
		Use:   "stat TARGET PATH",
		Short: "Stat a remote path (exists:false instead of an error when missing)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, _, _, err := oneHost(cmd.Context(), args[0], func(_ *store.State, _ *sshx.Client, sc *sftp.Client) (any, error) {
				p := expandRemote(sc, args[1])
				fi, err := sc.Lstat(p)
				if errors.Is(err, os.ErrNotExist) {
					return map[string]any{"path": p, "exists": false}, nil
				}
				if err != nil {
					return nil, fsErrHint(p, err, "check the permissions of the folders above it")
				}
				inf := toInfo(path.Dir(p), fi)
				if inf.Type == "symlink" {
					inf.Link, _ = sc.ReadLink(p)
				}
				r := map[string]any{"exists": true, "info": inf}
				if hash && inf.Type == "file" {
					f, err := sc.Open(p)
					if err != nil {
						return nil, fsErrHint(p, err, "fs stat --sha256 reads as the SSH user; use `komando exec --sudo -- sha256sum FILE`")
					}
					defer f.Close()
					h := sha256.New()
					if _, err := io.Copy(h, f); err != nil {
						return nil, err
					}
					r["sha256"] = hex.EncodeToString(h.Sum(nil))
				}
				return r, nil
			})
			if err != nil {
				return err
			}
			out.P.Print("fs.stat", res, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&hash, "sha256", false, "also compute sha256")
	return c
}

func readRemote(ctx context.Context, c *sshx.Client, sc *sftp.Client, p string, sudo bool, limit int64) ([]byte, bool, error) {
	if sudo {
		r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: "cat -- " + sshx.Q(p), Sudo: true, MaxOutput: int(limit), Timeout: 2 * time.Minute})
		if err != nil {
			return nil, false, err
		}
		if r.ExitCode != 0 {
			if strings.Contains(r.Stderr, "No such file") {
				return nil, false, fsErr(p, os.ErrNotExist)
			}
			if strings.Contains(r.Stderr, "Is a directory") {
				return nil, false, isADirectory(p)
			}
			return nil, false, out.Errf(out.ExitRemote, "READ_FAILED", "check the path and its permissions with `komando fs stat TARGET PATH`, or add --sudo", "%s", strings.TrimSpace(r.Stderr))
		}
		return []byte(r.Stdout), r.StdoutTruncated, nil
	}
	if fi, err := sc.Stat(p); err == nil && fi.IsDir() {
		return nil, false, isADirectory(p)
	}
	f, err := sc.Open(p)
	if err != nil {
		return nil, false, fsErr(p, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, fsErr(p, err)
	}
	if int64(len(b)) > limit {
		return b[:limit], true, nil
	}
	return b, false, nil
}

func isADirectory(p string) error {
	return out.Errf(out.ExitUsage, "IS_A_DIRECTORY", "list it with `komando fs ls`", "%s is a folder, not a file", p)
}

type catResult struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Bytes     int    `json:"bytes"`
	Lines     int    `json:"lines"`
	Truncated bool   `json:"truncated"`
	Binary    bool   `json:"binary,omitempty"`
	SHA256    string `json:"sha256,omitempty"` // of the whole file
	// SHA256Read: the file was longer than --max-bytes; this is the hash
	// of the part that was read, not of the file
	SHA256Read string `json:"sha256_read,omitempty"`
	Note       string `json:"note,omitempty"`
}

func (r catResult) Text() string { return r.Content }

func fsCatCmd() *cobra.Command {
	var sudo bool
	var maxBytes int64
	var head, tail int
	var numbered bool
	c := &cobra.Command{
		Use:     "cat TARGET PATH",
		Aliases: []string{"read"},
		Short:   "Read a remote file (with --head/--tail/--line-numbers for agents)",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if maxBytes <= 0 {
				return out.Usage("--max-bytes must be more than 0")
			}
			res, _, _, err := oneHost(cmd.Context(), args[0], func(_ *store.State, c *sshx.Client, sc *sftp.Client) (any, error) {
				p := expandRemote(sc, args[1])
				b, trunc, err := readRemote(cmd.Context(), c, sc, p, sudo, maxBytes)
				if err != nil {
					return nil, err
				}
				return catContent(args[0], p, b, trunc, head, tail, numbered)
			})
			if err != nil {
				return err
			}
			out.P.Print("fs.cat", res, nil)
			if r, ok := res.(catResult); ok && r.Truncated && out.P.Format == "text" {
				fmt.Fprintf(os.Stderr, "note: output truncated at %s (raise --max-bytes, or use `komando download`)\n", humanBytes(maxBytes))
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&sudo, "sudo", "s", false, "read via sudo")
	c.Flags().Int64Var(&maxBytes, "max-bytes", 1<<20, "max bytes to read")
	c.Flags().IntVar(&head, "head", 0, "only first N lines")
	c.Flags().IntVar(&tail, "tail", 0, "only last N lines")
	c.Flags().BoolVar(&numbered, "line-numbers", false, "prefix line numbers")
	aliasFlag(c.Flags(), "number", "line-numbers")
	return c
}

// catContent is fs cat's result for the file p of target, read as b.
func catContent(target, p string, b []byte, trunc bool, head, tail int, numbered bool) (catResult, error) {
	sum := hex.EncodeToString(func() []byte { h := sha256.Sum256(b); return h[:] }())
	r := catResult{Path: p, Bytes: len(b), Truncated: trunc}
	binary := bytes.IndexByte(b, 0) >= 0
	text := string(b)
	if out.P.Mask && !binary {
		// mask the whole file before --head/--tail cut it: what marks a
		// value as secret can sit outside the lines shown
		text = out.P.View(text).Text
		if text != string(b) {
			// the hash of the real file would let a weak hidden value be
			// guessed offline from the rest
			sum = ""
		}
	}
	if trunc {
		r.SHA256Read = sum
	} else {
		r.SHA256 = sum
	}
	if binary {
		if out.P.Format == "text" {
			// printing a placeholder would make `fs cat ... > file` a corrupt copy
			return catResult{}, out.Errf(out.ExitError, "BINARY_FILE", "save it with `komando download "+target+" "+p+"`",
				"%s is a binary file; fs cat shows text only", p)
		}
		r.Binary = true
		r.Content = "<binary content omitted; use `komando download` to save it>"
		return r, nil
	}
	lines := strings.SplitAfter(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	r.Lines = len(lines)
	if text != string(b) && strings.Count(text, "\n") != strings.Count(string(b), "\n") {
		r.Note = "a hidden private key shows as one line; lines and line numbers count the file as shown"
	}
	start := 0
	if head > 0 && head < len(lines) {
		lines = lines[:head]
	}
	if tail > 0 && tail < len(lines) {
		start = len(lines) - tail
		lines = lines[start:]
	}
	if numbered {
		for i := range lines {
			lines[i] = fmt.Sprintf("%6d\t%s", start+i+1, lines[i])
		}
	}
	r.Content = strings.Join(lines, "")
	return r, nil
}

type writeOpts struct {
	sudo, backup, mkdirs bool
	noFollow             bool // refuse a symlink instead of writing its target
	mode                 string
	owner                string
	validate             string // command run on the new file (%s) before it goes into place
}

// validateCmd puts the quoted temporary path where --validate has %s.
func (o writeOpts) validateCmd(tmp string) string {
	return strings.ReplaceAll(o.validate, "%s", sshx.Q(tmp))
}

func validateFailed(stderr string) error {
	return out.Errf(out.ExitConflict, "VALIDATION_FAILED", "the file was not changed; fix the content and try again",
		"--validate rejected the new file: %s", strings.TrimSpace(stderr))
}

// writeRemote writes data atomically (temp file + rename) and returns info.
func writeRemote(ctx context.Context, c *sshx.Client, sc *sftp.Client, p string, data []byte, o writeOpts) (map[string]any, error) {
	return writeRemoteFrom(ctx, c, sc, p, bytes.NewReader(data), o)
}

// writeRemoteFrom is writeRemote for a stream: the content goes to the
// server as it is read, so files of any size never sit in memory.
func writeRemoteFrom(ctx context.Context, c *sshx.Client, sc *sftp.Client, p string, src io.Reader, o writeOpts) (map[string]any, error) {
	res := map[string]any{"path": p}
	h := sha256.New()
	copyIn := func(f io.Writer) error {
		n, err := io.Copy(io.MultiWriter(f, h), src)
		res["bytes"], res["sha256"] = n, hex.EncodeToString(h.Sum(nil))
		return err
	}
	mode := o.mode
	if mode != "" {
		if _, err := strconv.ParseUint(mode, 8, 32); err != nil {
			return nil, out.Usage("invalid --mode %q", mode)
		}
	}
	if o.owner != "" && !o.sudo {
		return nil, out.Usage("--owner needs --sudo (only root can give a file to another user)")
	}
	tmpName := fmt.Sprintf(".komando-%d-%s", time.Now().UnixNano(), path.Base(p))
	if o.sudo {
		// stage in the user's tmp then sudo install into place
		tmp := path.Join("/tmp", tmpName)
		f, err := sc.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return nil, fsErr(tmp, err)
		}
		// only the SSH user may read the staged content (it can be a secret)
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			sc.Remove(tmp)
			return nil, fsErr(tmp, err)
		}
		if err := copyIn(f); err != nil {
			f.Close()
			sc.Remove(tmp)
			return nil, err
		}
		f.Close()
		var sb strings.Builder
		sb.WriteString("set -e; p=" + sshx.Q(p) + "; ")
		// a symlink (sites-enabled -> sites-available): write the file it
		// names, so the link stays a link
		if o.noFollow {
			sb.WriteString(`if [ -L "$p" ]; then rm -f ` + sshx.Q(tmp) + `; exit 95; fi; `)
		} else {
			sb.WriteString(`if [ -L "$p" ]; then p=$(readlink -f -- "$p"); fi; `)
		}
		if o.mkdirs {
			sb.WriteString(`mkdir -p "$(dirname -- "$p")"; `)
		} else {
			sb.WriteString(`if [ ! -d "$(dirname -- "$p")" ]; then rm -f ` + sshx.Q(tmp) + `; exit 96; fi; `)
		}
		// keep the mode of the existing file; read it as root, because the SSH
		// user often cannot see into the directory (/etc/sudoers.d, /root)
		if mode == "" {
			sb.WriteString(`m=$(stat -c %a "$p" 2>/dev/null || echo 644); `)
		} else {
			sb.WriteString("m=" + mode + "; ")
		}
		if o.validate != "" {
			// exit 97 tells komando the check failed, not the install
			sb.WriteString("if ! ( " + o.validateCmd(tmp) + " ) >&2; then rm -f " + sshx.Q(tmp) + "; exit 97; fi; ")
		}
		sb.WriteString(`r=0; if [ -e "$p" ]; then r=1; fi; k=-; `)
		if o.backup {
			sb.WriteString(sudoBackupScript(sshx.Q(tmp), time.Now()))
		}
		// keep owner of existing file unless --owner given
		owner := o.owner
		if owner == "" {
			sb.WriteString(`o=$(stat -c %u:%g "$p" 2>/dev/null || echo 0:0); `)
			sb.WriteString(`install -m "$m" -o "${o%:*}" -g "${o#*:}" ` + sshx.Q(tmp) + ` "$p"; `)
		} else {
			u, gr, _ := strings.Cut(owner, ":")
			sb.WriteString(`install -m "$m" -o ` + sshx.Q(u))
			if gr != "" {
				sb.WriteString(" -g " + sshx.Q(gr))
			}
			sb.WriteString(" " + sshx.Q(tmp) + ` "$p"; `)
		}
		sb.WriteString("rm -f " + sshx.Q(tmp) + `; printf '%s %s %s %s\n' "$m" "$r" "$k" "$p"`)
		r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: sb.String(), Sudo: true, Timeout: time.Minute, MaxOutput: 64 << 10})
		if err != nil {
			_ = sc.Remove(tmp)
			return nil, err
		}
		switch {
		case r.ExitCode == 97 && o.validate != "":
			return nil, validateFailed(r.Stderr)
		case r.ExitCode == 95:
			return nil, isASymlink(p)
		case r.ExitCode == 94 && o.backup:
			return nil, backupFailed(p, r.Stderr)
		case r.ExitCode == 96:
			return nil, folderMissing(path.Dir(p))
		case r.ExitCode != 0:
			_ = sc.Remove(tmp)
			return nil, out.Errf(out.ExitRemote, "WRITE_FAILED", "check that the folder is writable and has free space: `komando exec TARGET --read-only -- df -h`", "%s", strings.TrimSpace(r.Stderr))
		}
		f4 := strings.SplitN(strings.TrimSpace(r.Stdout), " ", 4)
		if len(f4) == 4 {
			mode = fmt.Sprintf("%04s", f4[0])
			res["replaced"] = f4[1] == "1"
			if f4[3] != p {
				res["followed"] = f4[3]
			}
			if o.backup && f4[2] != "-" {
				res["backup"] = f4[3] + "." + f4[2]
			}
		}
		res["mode"] = mode
		return res, nil
	}
	if fi, err := sc.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if o.noFollow {
			return nil, isASymlink(p)
		}
		t, err := resolveLink(sc, p)
		if err != nil {
			return nil, err
		}
		res["followed"] = t
		p = t
	}
	dir := path.Dir(p)
	if o.mkdirs {
		if err := sc.MkdirAll(dir); err != nil {
			return nil, fsErr(dir, err)
		}
	} else if fi, err := sc.Stat(dir); err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, folderMissing(dir)
	} else if err == nil && !fi.IsDir() {
		return nil, out.Errf(out.ExitConflict, "NOT_A_FOLDER", "give a folder path, not a file", "%s is a file, not a folder", dir)
	}
	// preserve the existing mode when not specified
	existing, statErr := sc.Stat(p)
	res["replaced"] = statErr == nil
	if mode == "" {
		if statErr == nil {
			mode = fmt.Sprintf("%04o", existing.Mode().Perm())
		} else {
			mode = "0644"
		}
	}
	perm, _ := strconv.ParseUint(mode, 8, 32)
	tmp := path.Join(dir, tmpName)
	// exclusive: never write into a file, or through a link, already there
	f, err := sc.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return nil, fsErr(dir, err)
	}
	// only the SSH user may read the content while it goes in (it can be a
	// secret); the final mode is set before the file goes into place
	_, err = chmodOpen(f, tmp, 0o600)
	if err == nil {
		err = copyIn(f)
	}
	got := os.FileMode(perm)
	if err == nil {
		got, err = chmodOpen(f, tmp, os.FileMode(perm))
	}
	if cerr := f.Close(); err == nil && cerr != nil {
		err = fsErr(tmp, cerr)
	}
	if err != nil {
		sc.Remove(tmp)
		return nil, err
	}
	if o.validate != "" {
		r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: o.validateCmd(tmp), Timeout: time.Minute, MaxOutput: 64 << 10})
		if err != nil || r.ExitCode != 0 {
			sc.Remove(tmp)
			if err != nil {
				return nil, err
			}
			return nil, validateFailed(r.Stderr + r.Stdout)
		}
	}
	// after --validate, so a rejected edit leaves no backup behind
	if o.backup && statErr == nil {
		b, err := backupRemote(sc, p, time.Now())
		if err != nil {
			sc.Remove(tmp)
			return nil, err
		}
		res["backup"] = b
	}
	if err := sc.PosixRename(tmp, p); err != nil {
		if err2 := sc.Rename(tmp, p); err2 != nil {
			sc.Remove(tmp)
			return nil, fsErr(p, err)
		}
	}
	res["mode"] = mode
	if got != os.FileMode(perm) {
		res["mode"] = fmt.Sprintf("%04o", got)
		res["note"] = fmt.Sprintf("the server does not allow setting file modes; the file has mode %04o, not %s", got, mode)
	}
	return res, nil
}

// backupStamp is the UTC time in a backup's name when PATH.bak is taken.
const backupStamp = "20060102T150405Z"

// backupName is the name a new backup of p gets: PATH.bak, or when that is
// taken (an earlier backup, or one a person made) PATH.bak.<UTC time>, then
// PATH.bak.<UTC time>-2 and so on. A backup is never overwritten.
func backupName(p string, now time.Time, taken func(string) bool) string {
	b := p + ".bak"
	if !taken(b) {
		return b
	}
	ts := b + "." + now.UTC().Format(backupStamp)
	b = ts
	for n := 2; taken(b); n++ {
		b = fmt.Sprintf("%s-%d", ts, n)
	}
	return b
}

// sudoBackupScript is backupName and backupRemote as root, in the shell:
// it sets $k to the backup's suffix ("bak", "bak.<UTC time>", ...), or
// exits 94. The shell creates the backup exclusively (noclobber), so root
// never writes through a link someone planted under the name, and with
// umask 077: the backup is root's alone (0600), whatever the file's mode.
func sudoBackupScript(qtmp string, now time.Time) string {
	ts := now.UTC().Format(backupStamp)
	return `if [ -e "$p" ]; then k=bak; ` +
		`if [ -e "$p.$k" ] || [ -L "$p.$k" ]; then k=bak.` + ts + `; i=1; ` +
		`while [ -e "$p.$k" ] || [ -L "$p.$k" ]; do i=$((i+1)); k=bak.` + ts + `-$i; done; fi; ` +
		`if ! ( umask 077; set -C; cat -- "$p" > "$p.$k" ); then rm -f ` + qtmp + `; exit 94; fi; fi; `
}

func backupFailed(p, stderr string) error {
	return out.Errf(out.ExitRemote, "BACKUP_FAILED", "the file was not changed; check free space with `komando exec TARGET --read-only -- df -h`, or run without --backup",
		"could not make a backup of %s: %s", p, strings.TrimSpace(stderr))
}

// chmodOpen sets the mode of a file komando has open, through its handle,
// so a link put in its place cannot redirect it, and returns the mode the
// file has. Some SFTP servers (storage boxes, chrooted SFTP-only accounts,
// vfat or CIFS mounts) do not allow setting a mode: that is fine when the
// file already has no more permissions than asked for, and refused when it
// would end up more open.
func chmodOpen(f *sftp.File, p string, mode os.FileMode) (os.FileMode, error) {
	err := f.Chmod(mode)
	if err == nil {
		return mode.Perm(), nil
	}
	if fi, serr := f.Stat(); serr == nil && fi.Mode().Perm()&^mode.Perm() == 0 {
		return fi.Mode().Perm(), nil
	}
	return 0, out.Errf(out.ExitRemote, "CHMOD_FAILED", "the file was not changed. This SFTP server does not allow setting file modes, and its new files are more open than asked for; if the server has a shell and sudo, retry with --sudo",
		"cannot set mode %04o on %s: %v", mode.Perm(), p, err)
}

// backupRemote copies the file p to a new backup next to it (backupName)
// and returns its path. The backup is created exclusively, so a file or a
// link already under the name is never written to, and only the SSH user
// can read it until it is complete; then it gets p's mode.
func backupRemote(sc *sftp.Client, p string, now time.Time) (string, error) {
	in, err := sc.Open(p)
	if err != nil {
		return "", fsErr(p, err)
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return "", fsErr(p, err)
	}
	taken := func(n string) bool { _, err := sc.Lstat(n); return err == nil }
	for try := 0; ; try++ {
		b := backupName(p, now, taken)
		o, err := sc.OpenFile(b, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			if try < 3 && taken(b) {
				continue // made by someone else a moment ago
			}
			return "", fsErr(b, err)
		}
		_, err = chmodOpen(o, b, 0o600)
		if err == nil {
			_, err = io.Copy(o, in)
		}
		if err == nil {
			_, err = chmodOpen(o, b, fi.Mode().Perm())
		}
		if cerr := o.Close(); err == nil && cerr != nil {
			err = cerr
		}
		if err != nil {
			sc.Remove(b)
			return "", fsErr(b, err)
		}
		return b, nil
	}
}

func fsWriteCmd() *cobra.Command {
	var o writeOpts
	var content, from string
	var appendMode, ifChanged bool
	c := &cobra.Command{
		Use:   "write TARGET PATH",
		Short: "Write a remote file atomically (content from --content, --from FILE, or stdin)",
		Example: `  komando fs write web1 /etc/app/env --content 'PORT=8080' --sudo --backup
  komando fs write web1 /srv/app/config.yml --from ./config.yml --if-changed`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var data []byte
			var err error
			switch {
			case cmd.Flags().Changed("content"):
				data = []byte(content)
			case from != "":
				if data, err = readFileOrStdin(from); err != nil {
					return err
				}
			default:
				if data, err = readStdinIfPiped(); err != nil {
					return err
				}
				if data == nil {
					return out.Usage("provide --content, --from FILE, or pipe data on stdin")
				}
			}
			if out.HasHidden(string(data)) {
				return hiddenValueErr()
			}
			if data, err = expandSecretRefsBytes(data); err != nil {
				return err
			}
			if o.owner != "" && !o.sudo {
				return out.Usage("--owner needs --sudo (only root can give a file to another user)")
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			h, err := oneServer(st, args[0], "to put one file on many servers use `komando upload "+args[0]+" FILE PATH`")
			if err != nil {
				return err
			}
			if err := checkValidate(o.validate); err != nil {
				return err
			}
			if err := guard(st, []*store.Host{h}, o.validate, true); err != nil {
				return err
			}
			if g.dryRun {
				// read the current file (read-only) so the preview shows the change
				res := fsChange{"host": h.Name, "path": args[1], "bytes": len(data), "append": appendMode, "sudo": o.sudo}
				err := withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
					sc, err := sftpClient(c)
					if err != nil {
						return err
					}
					defer sc.Close()
					p := expandRemote(sc, args[1])
					res["path"] = p
					if t, err := resolveLink(sc, p); err == nil && t != p {
						if o.noFollow {
							return isASymlink(p)
						}
						res["followed"] = t
					}
					old, trunc, rerr := readRemote(cmd.Context(), c, sc, p, o.sudo, 1<<20)
					switch {
					case rerr != nil && toErr(rerr).Code == "PATH_NOT_FOUND":
						old, res["exists"] = nil, false
					case rerr != nil:
						return rerr
					case trunc || !utf8.Valid(old) || !utf8.Valid(data):
						res["diff_skipped"] = "file larger than 1 MiB or not text"
						return nil
					}
					updated := data
					if appendMode {
						updated = append(append([]byte(nil), old...), data...)
					}
					res["would_change"] = !sameForAgent(old, updated)
					res["diff"] = unifiedDiff(string(old), string(updated), 3)
					return nil
				})
				if err != nil {
					return err
				}
				out.P.Print("fs.write", res, nil)
				return nil
			}
			var res fsChange
			err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
				sc, err := sftpClient(c)
				if err != nil {
					return err
				}
				defer sc.Close()
				p := expandRemote(sc, args[1])
				if appendMode || ifChanged {
					old, trunc, rerr := readRemote(cmd.Context(), c, sc, p, o.sudo, 64<<20)
					if rerr != nil && toErr(rerr).Code != "PATH_NOT_FOUND" {
						return rerr
					}
					if appendMode {
						if trunc {
							return out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "append to it with exec instead, e.g. `cat >> FILE`", "file larger than 64MiB")
						}
						data = append(old, data...)
					}
					if ifChanged && rerr == nil && sameForAgent(old, data) {
						res = fsChange{"path": p, "changed": false}
						return nil
					}
				}
				w, err := writeRemote(cmd.Context(), c, sc, p, data, o)
				if w != nil {
					res = fsChange(w)
					res["changed"] = true
					if out.P.Mask && out.P.View(string(data)).Text != string(data) {
						delete(res, "sha256") // see fs replace
					}
				}
				return err
			})
			audit(st, "fs.write", []string{h.Name}, "", err == nil, map[string]any{"path": args[1]})
			if err != nil {
				return err
			}
			out.P.Print("fs.write", res, nil)
			return nil
		},
	}
	c.Flags().StringVar(&content, "content", "", "literal content")
	c.Flags().StringVar(&from, "from", "", "local source file ('-' = stdin)")
	c.Flags().BoolVar(&appendMode, "append", false, "append instead of overwrite")
	c.Flags().BoolVar(&ifChanged, "if-changed", false, "skip the write when content is identical (idempotent)")
	bindWriteOpts(c, &o)
	return c
}

func bindWriteOpts(c *cobra.Command, o *writeOpts) {
	c.Flags().BoolVarP(&o.sudo, "sudo", "s", false, "write via sudo (root-owned paths)")
	c.Flags().BoolVar(&o.backup, "backup", false, "keep the previous version as PATH.bak (PATH.bak.<UTC time> when that exists; a backup is never overwritten)")
	c.Flags().BoolVarP(&o.mkdirs, "parents", "p", false, "create parent directories")
	c.Flags().StringVar(&o.mode, "mode", "", "file mode, e.g. 0640 (default: keep existing or 0644)")
	c.Flags().StringVar(&o.owner, "owner", "", "owner[:group] (requires --sudo)")
	c.Flags().StringVar(&o.validate, "validate", "", "check the new file before it goes into place; %s is its path (e.g. 'visudo -cf %s', 'nginx -t -c %s')")
	c.Flags().BoolVar(&o.noFollow, "no-follow", false, "refuse to write through a symbolic link (by default the file it points to is written and the link stays)")
}

func fsReplaceCmd() *cobra.Command {
	var o writeOpts
	var oldS, newS string
	var all, isRegex bool
	c := &cobra.Command{
		Use:   "replace TARGET PATH --old TEXT --new TEXT",
		Short: "Edit a remote file by exact (or --regex) replacement; fails if not found or ambiguous",
		Example: `  komando fs replace web1 /etc/nginx/nginx.conf --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup
  komando fs replace web1 /etc/ssh/sshd_config --regex --old '(?m)^#?PasswordAuthentication .*$' --new 'PasswordAuthentication no' --sudo`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if oldS == "" {
				return out.Usage("--old is required")
			}
			if out.HasHidden(newS) {
				return hiddenValueErr()
			}
			newS, err := expandSecretRefs(newS)
			if err != nil {
				return err
			}
			var re *regexp.Regexp
			switch {
			case isRegex:
				if re, err = regexp.Compile(oldS); err != nil {
					return out.Usage("invalid regex: %v", err)
				}
			case strings.Contains(oldS, out.Hidden) && !out.P.Mask:
				// a line an AI agent saw masked: [hidden] stands for the value
				// (an agent's own run finds it as it is, in out.View)
				if re, err = regexp.Compile(hiddenPattern(oldS)); err != nil {
					return out.Usage("--old: %v", err)
				}
				newS = strings.ReplaceAll(newS, "$", "$$")
			}
			if o.owner != "" && !o.sudo {
				return out.Usage("--owner needs --sudo (only root can give a file to another user)")
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			h, err := oneServer(st, args[0], "fs replace edits one server's file; run it per server, or use `komando exec "+args[0]+" -- sed ...` for many")
			if err != nil {
				return err
			}
			if err := checkValidate(o.validate); err != nil {
				return err
			}
			if err := guard(st, []*store.Host{h}, o.validate, true); err != nil {
				return err
			}
			var res fsChange
			err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
				sc, err := sftpClient(c)
				if err != nil {
					return err
				}
				defer sc.Close()
				p := expandRemote(sc, args[1])
				b, trunc, err := readRemote(cmd.Context(), c, sc, p, o.sudo, 64<<20)
				if err != nil {
					return err
				}
				if trunc {
					return out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "for a bigger file: `komando download` it, edit it here, then `komando upload` it", "%s is larger than 64MiB, the most fs replace edits", p)
				}
				src := string(b)
				pl, err := planReplace(out.P, src, oldS, newS, re, all, args[1])
				if err != nil {
					return err
				}
				if !pl.changed {
					res = fsChange{"path": p, "changed": false, "replacements": pl.n}
					if pl.note != "" {
						res["note"] = pl.note
					}
					return nil
				}
				res = fsChange{"path": p, "changed": true, "replacements": pl.n, "diff": unifiedDiff(pl.view, pl.shown, 3)}
				if g.dryRun {
					delete(res, "changed")
					res["would_change"] = true
					if t, err := resolveLink(sc, p); err == nil && t != p {
						res["followed"] = t
					}
					return nil
				}
				w, err := writeRemote(cmd.Context(), c, sc, p, []byte(pl.updated), o)
				if err != nil {
					return err
				}
				for k, v := range w {
					res[k] = v
				}
				if pl.view != src {
					// a hash of the real file would let a weak hidden value be
					// guessed offline from the rest, which the agent saw
					delete(res, "sha256")
				}
				return nil
			})
			audit(st, "fs.replace", []string{h.Name}, "", err == nil, map[string]any{"path": args[1]})
			if err != nil {
				return err
			}
			out.P.Print("fs.replace", res, nil)
			return nil
		},
	}
	c.Flags().StringVar(&oldS, "old", "", "text (or regex with --regex) to find")
	c.Flags().StringVar(&newS, "new", "", "replacement text ($1 groups with --regex)")
	c.Flags().BoolVar(&all, "all", false, "replace every occurrence")
	c.Flags().BoolVar(&isRegex, "regex", false, "treat --old as a Go regular expression")
	bindWriteOpts(c, &o)
	return c
}

// sameForAgent: fs write would leave the file as it is. For an AI agent
// a file with a value komando hides always counts as changed (and is
// written again), so --if-changed and would_change never confirm that the
// content the agent wrote guessed the hidden value.
func sameForAgent(old, data []byte) bool {
	if out.P.Mask && out.P.View(string(old)).Masked() {
		return false
	}
	return bytes.Equal(old, data)
}

// replacePlan is what fs replace does to a file: the new file (updated),
// and the file and the new file as the caller sees them (view, shown).
type replacePlan struct {
	updated, view, shown string
	n                    int // matches of --old
	changed              bool
	note                 string
}

// planReplace edits src as p shows it. For an AI agent (p.Mask) the file
// is the masked view: every answer (no match, no change, already applied,
// the diff) depends only on what the agent saw, never on a hidden value.
func planReplace(p *out.Printer, src, oldS, newS string, re *regexp.Regexp, all bool, name string) (replacePlan, error) {
	view := out.View{Text: src}
	if p.Mask {
		view = p.View(src)
	}
	pl := replacePlan{view: view.Text}
	locs := findOld(view.Text, oldS, re)
	pl.n = len(locs)
	if pl.n == 0 {
		if re == nil && newS != "" && alreadyThere(p, view.Text, newS) {
			pl.note = "old text not found but new text already present (already applied?)"
			return pl, nil
		}
		return pl, out.Errf(out.ExitConflict, "NO_MATCH", "read the file with `komando fs cat` and copy the exact text (whitespace matters)", "--old text not found in %s", name)
	}
	if pl.n > 1 && !all {
		return pl, out.Errf(out.ExitConflict, "AMBIGUOUS_MATCH", "add surrounding context to --old so it is unique, or pass --all", "--old matches %d times in %s", pl.n, name)
	}
	if !all {
		locs = locs[:1]
	}
	var err error
	if pl.updated, pl.shown, err = replaceOld(view, src, locs, newS, re); err != nil {
		return pl, err
	}
	if !p.Mask {
		pl.changed = pl.updated != src
		return pl, nil
	}
	// decided on the view: whether the real bytes stay the same would say
	// whether --new guessed a hidden value (the same bytes are then written)
	pl.changed = pl.shown != view.Text
	// an edit can leave a hidden value in place but take away what made it
	// look secret (DB_PASSWORD= renamed, postgres:// or Bearer cut off): the
	// next fs cat would show it. The new file, as it will be shown, must not
	// hold a hidden value more often than the edit the agent asked for does.
	now, asked := p.View(pl.updated).Text, p.View(pl.shown).Text
	for _, v := range view.Hidden(src) {
		if v != "" && strings.Count(now, v) > strings.Count(asked, v) {
			return pl, out.Errf(out.ExitUsage, "HIDDEN_VALUE", "keep the name or text around a hidden value that marks it as secret, or replace the value too, e.g. --old 'NAME=[hidden]' --new 'NAME={{secret:VAULT_NAME}}'",
				"the edit would show a value komando hid")
		}
	}
	return pl, nil
}

// alreadyThere: --new, as the caller would see it, is in the file as the
// caller sees it. A --new that spells out a value komando hides is never
// reported as there, or the answer would confirm a guessed value.
func alreadyThere(p *out.Printer, view, newS string) bool {
	if !p.Mask {
		return strings.Contains(view, newS)
	}
	nv := p.View(newS)
	return !nv.Masked() && strings.Contains(view, nv.Text)
}

// findOld returns where --old matches in text, not overlapping: the
// regexp's submatch indexes, or [start, end] of the exact text.
func findOld(text, oldS string, re *regexp.Regexp) [][]int {
	if re != nil {
		return re.FindAllStringSubmatchIndex(text, -1)
	}
	var locs [][]int
	for i := 0; ; {
		j := strings.Index(text[i:], oldS)
		if j < 0 {
			return locs
		}
		locs = append(locs, []int{i + j, i + j + len(oldS)})
		i += j + len(oldS)
	}
}

// replaceOld puts --new (with $1 groups for a regexp) at the matches locs
// of v.Text. It returns the new file, edited where each match is in src,
// and the new text as shown (the diff). A match that cuts into a hidden
// value, or a replacement that copies one ([hidden] captured by a group),
// is refused: the real value is never moved anywhere the agent could see it.
func replaceOld(v out.View, src string, locs [][]int, newS string, re *regexp.Regexp) (updated, shown string, err error) {
	var ub, sb strings.Builder
	lastT, lastS := 0, 0
	for _, loc := range locs {
		r := newS
		if re != nil {
			r = string(re.ExpandString(nil, newS, v.Text, loc))
		}
		a, e, ok := v.Source(loc[0], loc[1])
		if !ok {
			return "", "", out.Errf(out.ExitUsage, "HIDDEN_VALUE", "match a hidden value whole: [hidden] in --old (without --regex) stands for it",
				"--old starts or ends inside a value komando hid")
		}
		if v.Text != src && out.HasHidden(r) {
			return "", "", hiddenValueErr()
		}
		sb.WriteString(v.Text[lastT:loc[0]])
		sb.WriteString(r)
		ub.WriteString(src[lastS:a])
		ub.WriteString(r)
		lastT, lastS = loc[1], e
	}
	sb.WriteString(v.Text[lastT:])
	ub.WriteString(src[lastS:])
	return ub.String(), sb.String(), nil
}

// shellFsCmd builds simple mutating fs commands executed via the shell so
// that --sudo works uniformly. build returns the script and the short
// command shown in output and the audit log.
func shellFsCmd(use, short string, minArgs int, build func(args []string, flags map[string]bool) (script, shown string, err error), boolFlags map[string]string) *cobra.Command {
	var sudo bool
	vals := map[string]*bool{}
	c := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.MinimumNArgs(minArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			fl := map[string]bool{}
			for k, v := range vals {
				fl[k] = *v
			}
			if strings.HasPrefix(use, "rm ") && fl["recursive"] && !dangerOK() {
				if err := policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "a folder and everything in it would be gone; confirm with the user, then add --allow-dangerous",
					"rm --recursive deletes whole folders")); err != nil {
					return err
				}
			}
			if strings.HasPrefix(use, "rm ") {
				for _, p := range args[1:] {
					if cp := path.Clean(p); (cp == "/" || cp == "." || cp == "~" || strings.Count(cp, "/") <= 1 && strings.HasPrefix(cp, "/")) && !dangerOK() {
						if err := policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "pass --allow-dangerous if truly intended",
							"refusing to remove top-level path %q", p)); err != nil {
							return err
						}
					}
				}
			}
			script, shown, err := build(args[1:], fl)
			if err != nil {
				return err
			}
			return runFleet(cmd.Context(), "fs."+strings.Fields(use)[0], args[0], script, nil, execOpts{sudo: sudo, display: shown, exitMap: fsExitMap}, true)
		},
	}
	c.Flags().BoolVarP(&sudo, "sudo", "s", false, "run via sudo")
	for name, help := range boolFlags {
		v := new(bool)
		vals[name] = v
		if name == "recursive" {
			c.Flags().BoolVarP(v, name, "r", false, help)
		} else {
			c.Flags().BoolVar(v, name, false, help)
		}
	}
	return c
}

func quoteAll(a []string) string {
	q := make([]string, len(a))
	for i, s := range a {
		q[i] = sshx.Q(s)
	}
	return strings.Join(q, " ")
}

func fsRmCmd() *cobra.Command {
	c := shellFsCmd("rm TARGET PATH...", "Remove remote files (--recursive for folders); a missing path is reported, not an error", 2, func(a []string, f map[string]bool) (string, string, error) {
		flags := "-f"
		if f["recursive"] {
			flags = "-rf"
		}
		return rmScript(a, f["recursive"]), "rm " + flags + " -- " + rqAll(a), nil
	}, map[string]string{"recursive": "remove folders and everything in them"})
	c.Long = `Removes files like rm -f: a path that does not exist is reported ("not found")
and the command still succeeds. A folder needs --recursive, which also needs
--allow-dangerous. Paths are taken literally: '*.log' is not a pattern (use
komando exec for that).`
	return c
}

func fsMkdirCmd() *cobra.Command {
	return shellFsCmd("mkdir TARGET PATH...", "Create remote directories (always -p)", 2, func(a []string, _ map[string]bool) (string, string, error) {
		return mkdirScript(a), "mkdir -p -- " + rqAll(a), nil
	}, nil)
}

func fsMvCmd() *cobra.Command {
	c := shellFsCmd("mv TARGET SRC DST", "Move/rename a remote path; never replaces a file unless --overwrite", 3, func(a []string, f map[string]bool) (string, string, error) {
		if len(a) != 2 {
			return "", "", out.Usage("give one SRC and one DST: komando fs mv TARGET SRC DST")
		}
		return mvScript(a[0], a[1], f["overwrite"]), "mv -- " + rqAll(a), nil
	}, map[string]string{"overwrite": "replace DST if it exists"})
	c.Long = `Moves SRC to DST. When DST is an existing folder, SRC moves into it (like mv).
An existing file at the destination is never replaced unless --overwrite
(FILE_EXISTS, exit 8).`
	return c
}

func fsChmodCmd() *cobra.Command {
	return shellFsCmd("chmod TARGET MODE PATH...", "Change mode of remote paths", 3, func(a []string, f map[string]bool) (string, string, error) {
		if !validMode(a[0]) {
			hint := ""
			if validMode(a[len(a)-1]) {
				hint = " (the mode goes first: komando fs chmod TARGET MODE PATH)"
			}
			return "", "", out.Usage("%q is not a mode like 0644 or u+x%s", a[0], hint)
		}
		r := ""
		if f["recursive"] {
			r = "-R "
		}
		return chmodScript(a[0], a[1:], f["recursive"]), "chmod " + r + sshx.Q(a[0]) + " -- " + rqAll(a[1:]), nil
	}, map[string]string{"recursive": "recurse"})
}

func checkValidate(v string) error {
	if v != "" && !strings.Contains(v, "%s") {
		return out.Usage("--validate needs %%s where the new file's path goes, e.g. --validate 'visudo -cf %%s'")
	}
	return nil
}
