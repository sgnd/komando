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
			return nil, out.Usage("--mode %q is not an octal mode like 0644", mode)
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

// fsWriteInput is what fs write puts in the file: --content, --from FILE,
// or stdin; one of them, never a value komando hid.
func fsWriteInput(contentSet bool, content, from string) ([]byte, error) {
	var data []byte
	var err error
	switch {
	case contentSet && from != "":
		return nil, out.Usage("give the content with --content or --from, not both")
	case contentSet:
		data = []byte(content)
	case from != "":
		if data, err = readFileOrStdin(from); err != nil {
			return nil, err
		}
	default:
		if data, err = readStdinIfPiped(); err != nil {
			return nil, err
		}
		if data == nil {
			return nil, out.Usage("give the content with --content, --from FILE, or on stdin")
		}
	}
	if out.HasHidden(string(data)) {
		return nil, hiddenValueErr()
	}
	return data, nil
}

func fsWriteCmd() *cobra.Command {
	var o writeOpts
	var content, from string
	var appendMode, ifChanged bool
	c := &cobra.Command{
		Use:   "write TARGET PATH",
		Short: "Write a file on one server, all or nothing (--content, --from FILE or stdin)",
		Example: `  komando fs write web1 /etc/app/env --content 'PORT=8080' --sudo --backup
  komando fs write web1 /srv/app/config.yml --from ./config.yml --if-changed`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := fsWriteInput(cmd.Flags().Changed("content"), content, from)
			if err != nil {
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
			} else if h.Windows() {
				return winFsWrite(cmd.Context(), st, h, args[1], data, o, appendMode, ifChanged)
			}
			if err := checkValidate(o.validate); err != nil {
				return err
			}
			if err := guard(st, []*store.Host{h}, o.validate, true); err != nil {
				return err
			}
			if data, err = expandSecretRefsBytes(data, h.Name+":"+args[1]); err != nil {
				return err
			}
			if g.dryRun {
				return fsWritePreview(cmd.Context(), st, h, args[1], data, appendMode, o)
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
							return out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "append to it with exec instead, e.g. `cat >> FILE`", "the file is larger than 64MiB, the most fs write --append reads")
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
			printChange("fs.write", h.Name, res, o.sudo)
			return nil
		},
	}
	c.Flags().StringVar(&content, "content", "", "the content, written as given")
	c.Flags().StringVar(&from, "from", "", "file on this computer to send ('-' = stdin)")
	c.Flags().BoolVar(&appendMode, "append", false, "add to the end instead of replacing the file")
	c.Flags().BoolVar(&ifChanged, "if-changed", false, "skip the write when the content is the same (safe to run again)")
	bindWriteOpts(c, &o)
	return c
}

// fsWritePreview is fs write --dry-run: it reads the current file (only
// reads) so the preview shows the change.
func fsWritePreview(ctx context.Context, st *store.State, h *store.Host, p0 string, data []byte, appendMode bool, o writeOpts) error {
	res := fsChange{"host": h.Name, "path": p0, "bytes": len(data), "append": appendMode, "sudo": o.sudo}
	err := withClient(ctx, st, h, func(c *sshx.Client) error {
		sc, err := sftpClient(c)
		if err != nil {
			return err
		}
		defer sc.Close()
		p := expandRemote(sc, p0)
		res["path"] = p
		if t, err := resolveLink(sc, p); err == nil && t != p {
			if o.noFollow {
				return isASymlink(p)
			}
			res["followed"] = t
		}
		old, trunc, rerr := readRemote(ctx, c, sc, p, o.sudo, 1<<20)
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

func bindWriteOpts(c *cobra.Command, o *writeOpts) {
	c.Flags().BoolVarP(&o.sudo, "sudo", "s", false, "write with sudo (for files root owns)")
	c.Flags().BoolVar(&o.backup, "backup", false, "keep the previous version as PATH.bak (PATH.bak.<UTC time> when that exists; a backup is never overwritten)")
	c.Flags().BoolVarP(&o.mkdirs, "parents", "p", false, "create missing parent folders")
	c.Flags().StringVar(&o.mode, "mode", "", "file mode, e.g. 0640 (default: keep existing or 0644)")
	c.Flags().StringVar(&o.owner, "owner", "", "owner[:group] (needs --sudo)")
	c.Flags().StringVar(&o.validate, "validate", "", "check the new file before it goes into place; %s is its path (e.g. 'visudo -cf %s', 'nginx -t -c %s')")
	c.Flags().BoolVar(&o.noFollow, "no-follow", false, "refuse to write through a symbolic link (by default the file it points to is written and the link stays)")
}
