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
	switch {
	case errors.Is(err, os.ErrNotExist):
		return out.Errf(out.ExitNotFound, "PATH_NOT_FOUND", "", "%s: no such file or directory", p)
	case errors.Is(err, os.ErrPermission):
		return out.Errf(out.ExitError, "PERMISSION_DENIED", "retry with --sudo", "%s: permission denied", p)
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
		Use:   "ls TARGET PATH",
		Short: "List a remote directory",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, _, _, err := oneHost(cmd.Context(), args[0], func(_ *store.State, _ *sshx.Client, sc *sftp.Client) (any, error) {
				entries := []fileInfo{}
				truncated := false
				if recursive {
					w := sc.Walk(args[1])
					for w.Step() {
						if w.Err() != nil {
							continue
						}
						if w.Path() == args[1] {
							continue
						}
						if !all && strings.HasPrefix(path.Base(w.Path()), ".") {
							if w.Stat().IsDir() {
								w.SkipDir()
							}
							continue
						}
						if len(entries) >= maxEntries {
							truncated = true
							break
						}
						entries = append(entries, toInfo(path.Dir(w.Path()), w.Stat()))
					}
				} else {
					fis, err := sc.ReadDir(args[1])
					if err != nil {
						return nil, fsErr(args[1], err)
					}
					for _, fi := range fis {
						if !all && strings.HasPrefix(fi.Name(), ".") {
							continue
						}
						if len(entries) >= maxEntries {
							truncated = true
							break
						}
						entries = append(entries, toInfo(args[1], fi))
					}
				}
				return map[string]any{"path": args[1], "count": len(entries), "truncated": truncated, "entries": entries}, nil
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
				fi, err := sc.Lstat(args[1])
				if errors.Is(err, os.ErrNotExist) {
					return map[string]any{"path": args[1], "exists": false}, nil
				}
				if err != nil {
					return nil, fsErr(args[1], err)
				}
				inf := toInfo(path.Dir(args[1]), fi)
				if inf.Type == "symlink" {
					inf.Link, _ = sc.ReadLink(args[1])
				}
				r := map[string]any{"exists": true, "info": inf}
				if hash && inf.Type == "file" {
					f, err := sc.Open(args[1])
					if err != nil {
						return nil, fsErr(args[1], err)
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
			return nil, false, out.Errf(out.ExitRemote, "READ_FAILED", "", "%s", strings.TrimSpace(r.Stderr))
		}
		return []byte(r.Stdout), r.StdoutTruncated, nil
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

type catResult struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Bytes     int    `json:"bytes"`
	Lines     int    `json:"lines"`
	Truncated bool   `json:"truncated"`
	Binary    bool   `json:"binary,omitempty"`
	SHA256    string `json:"sha256"`
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
			res, _, _, err := oneHost(cmd.Context(), args[0], func(_ *store.State, c *sshx.Client, sc *sftp.Client) (any, error) {
				b, trunc, err := readRemote(cmd.Context(), c, sc, args[1], sudo, maxBytes)
				if err != nil {
					return nil, err
				}
				sum := sha256.Sum256(b)
				r := catResult{Path: args[1], Bytes: len(b), Truncated: trunc, SHA256: hex.EncodeToString(sum[:])}
				if bytes.IndexByte(b, 0) >= 0 {
					r.Binary = true
					r.Content = "<binary content omitted; use `komando cp` to download>"
					return r, nil
				}
				lines := strings.SplitAfter(string(b), "\n")
				if len(lines) > 0 && lines[len(lines)-1] == "" {
					lines = lines[:len(lines)-1]
				}
				r.Lines = len(lines)
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
			})
			if err != nil {
				return err
			}
			out.P.Print("fs.cat", res, nil)
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

type writeOpts struct {
	sudo, backup, mkdirs bool
	mode                 string
	owner                string
}

// writeRemote writes data atomically (temp file + rename) and returns info.
func writeRemote(ctx context.Context, c *sshx.Client, sc *sftp.Client, p string, data []byte, o writeOpts) (map[string]any, error) {
	res := map[string]any{"path": p, "bytes": len(data)}
	sum := sha256.Sum256(data)
	res["sha256"] = hex.EncodeToString(sum[:])
	dir := path.Dir(p)
	mode := o.mode
	// preserve the existing mode when not specified
	if mode == "" {
		if fi, err := sc.Stat(p); err == nil {
			mode = fmt.Sprintf("%04o", fi.Mode().Perm())
		} else {
			mode = "0644"
		}
	}
	perm, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return nil, out.Usage("invalid --mode %q", mode)
	}
	tmpName := fmt.Sprintf(".komando-%d-%s", time.Now().UnixNano(), path.Base(p))
	if o.sudo {
		// stage in the user's tmp then sudo install into place
		tmp := path.Join("/tmp", tmpName)
		f, err := sc.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return nil, fsErr(tmp, err)
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		var sb strings.Builder
		sb.WriteString("set -e; ")
		if o.mkdirs {
			sb.WriteString("mkdir -p " + sshx.Q(dir) + "; ")
		}
		if o.backup {
			sb.WriteString("if [ -e " + sshx.Q(p) + " ]; then cp -p " + sshx.Q(p) + " " + sshx.Q(p+".bak") + "; fi; ")
		}
		// keep owner of existing file unless --owner given
		owner := o.owner
		if owner == "" {
			sb.WriteString("o=$(stat -c %u:%g " + sshx.Q(p) + " 2>/dev/null || echo 0:0); ")
			sb.WriteString("install -m " + mode + " -o \"${o%:*}\" -g \"${o#*:}\" " + sshx.Q(tmp) + " " + sshx.Q(p) + "; ")
		} else {
			u, gr, _ := strings.Cut(owner, ":")
			sb.WriteString("install -m " + mode + " -o " + sshx.Q(u))
			if gr != "" {
				sb.WriteString(" -g " + sshx.Q(gr))
			}
			sb.WriteString(" " + sshx.Q(tmp) + " " + sshx.Q(p) + "; ")
		}
		sb.WriteString("rm -f " + sshx.Q(tmp))
		r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: sb.String(), Sudo: true, Timeout: time.Minute, MaxOutput: 64 << 10})
		if err != nil {
			return nil, err
		}
		if r.ExitCode != 0 {
			_ = sc.Remove(tmp)
			return nil, out.Errf(out.ExitRemote, "WRITE_FAILED", "", "%s", strings.TrimSpace(r.Stderr))
		}
		if o.backup {
			res["backup"] = p + ".bak"
		}
		res["mode"] = mode
		return res, nil
	}
	if o.mkdirs {
		if err := sc.MkdirAll(dir); err != nil {
			return nil, fsErr(dir, err)
		}
	}
	if o.backup {
		if _, err := sc.Stat(p); err == nil {
			if err := copyRemote(sc, p, p+".bak"); err != nil {
				return nil, err
			}
			res["backup"] = p + ".bak"
		}
	}
	tmp := path.Join(dir, tmpName)
	f, err := sc.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return nil, fsErr(tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		sc.Remove(tmp)
		return nil, err
	}
	f.Close()
	_ = sc.Chmod(tmp, os.FileMode(perm))
	if err := sc.PosixRename(tmp, p); err != nil {
		if err2 := sc.Rename(tmp, p); err2 != nil {
			sc.Remove(tmp)
			return nil, fsErr(p, err)
		}
	}
	res["mode"] = mode
	return res, nil
}

func copyRemote(sc *sftp.Client, src, dst string) error {
	in, err := sc.Open(src)
	if err != nil {
		return fsErr(src, err)
	}
	defer in.Close()
	o, err := sc.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fsErr(dst, err)
	}
	defer o.Close()
	_, err = io.Copy(o, in)
	if fi, e := in.Stat(); e == nil {
		_ = sc.Chmod(dst, fi.Mode().Perm())
	}
	return err
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
			st, err := loadState()
			if err != nil {
				return err
			}
			h, err := singleHost(st, args[0])
			if err != nil {
				return err
			}
			if err := guard(st, []*store.Host{h}, "", true); err != nil {
				return err
			}
			if g.dryRun {
				out.P.Print("fs.write", map[string]any{"host": h.Name, "path": args[1], "bytes": len(data), "append": appendMode, "sudo": o.sudo}, nil)
				return nil
			}
			var res map[string]any
			err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
				sc, err := sftpClient(c)
				if err != nil {
					return err
				}
				defer sc.Close()
				if appendMode || ifChanged {
					old, _, rerr := readRemote(cmd.Context(), c, sc, args[1], o.sudo, 64<<20)
					if rerr != nil && toErr(rerr).Code != "PATH_NOT_FOUND" {
						return rerr
					}
					if appendMode {
						data = append(old, data...)
					}
					if ifChanged && rerr == nil && bytes.Equal(old, data) {
						res = map[string]any{"path": args[1], "changed": false}
						return nil
					}
				}
				res, err = writeRemote(cmd.Context(), c, sc, args[1], data, o)
				if res != nil {
					res["changed"] = true
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
	c.Flags().BoolVar(&o.backup, "backup", false, "keep the previous version as PATH.bak")
	c.Flags().BoolVarP(&o.mkdirs, "parents", "p", false, "create parent directories")
	c.Flags().StringVar(&o.mode, "mode", "", "file mode, e.g. 0640 (default: keep existing or 0644)")
	c.Flags().StringVar(&o.owner, "owner", "", "owner[:group] (requires --sudo)")
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
			var re *regexp.Regexp
			if isRegex {
				var err error
				if re, err = regexp.Compile(oldS); err != nil {
					return out.Usage("invalid regex: %v", err)
				}
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			h, err := singleHost(st, args[0])
			if err != nil {
				return err
			}
			if err := guard(st, []*store.Host{h}, "", true); err != nil {
				return err
			}
			var res map[string]any
			err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
				sc, err := sftpClient(c)
				if err != nil {
					return err
				}
				defer sc.Close()
				b, trunc, err := readRemote(cmd.Context(), c, sc, args[1], o.sudo, 64<<20)
				if err != nil {
					return err
				}
				if trunc {
					return out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "", "file larger than 64MiB")
				}
				src := string(b)
				var n int
				var updated string
				if re != nil {
					n = len(re.FindAllStringIndex(src, -1))
				} else {
					n = strings.Count(src, oldS)
				}
				if n == 0 {
					if re == nil && strings.Contains(src, newS) && newS != "" {
						res = map[string]any{"path": args[1], "changed": false, "replacements": 0, "note": "old text not found but new text already present (already applied?)"}
						return nil
					}
					return out.Errf(out.ExitConflict, "NO_MATCH", "read the file with `komando fs cat` and copy the exact text (whitespace matters)", "--old text not found in %s", args[1])
				}
				if n > 1 && !all {
					return out.Errf(out.ExitConflict, "AMBIGUOUS_MATCH", "add surrounding context to --old so it is unique, or pass --all", "--old matches %d times in %s", n, args[1])
				}
				if re != nil {
					if all {
						updated = re.ReplaceAllString(src, newS)
					} else {
						loc := re.FindStringSubmatchIndex(src)
						var dst []byte
						dst = re.ExpandString(dst, newS, src, loc)
						updated = src[:loc[0]] + string(dst) + src[loc[1]:]
					}
				} else if all {
					updated = strings.ReplaceAll(src, oldS, newS)
				} else {
					updated = strings.Replace(src, oldS, newS, 1)
				}
				if updated == src {
					res = map[string]any{"path": args[1], "changed": false, "replacements": n}
					return nil
				}
				res = map[string]any{"path": args[1], "changed": true, "replacements": n, "diff": unifiedDiff(src, updated, 2)}
				if g.dryRun {
					return nil
				}
				w, err := writeRemote(cmd.Context(), c, sc, args[1], []byte(updated), o)
				if err != nil {
					return err
				}
				for k, v := range w {
					res[k] = v
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

// unifiedDiff produces a compact line diff (changed hunks with context).
func unifiedDiff(a, b string, ctx int) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	// trim common prefix/suffix, which is enough for replace-style edits
	p := 0
	for p < len(al) && p < len(bl) && al[p] == bl[p] {
		p++
	}
	s := 0
	for s < len(al)-p && s < len(bl)-p && al[len(al)-1-s] == bl[len(bl)-1-s] {
		s++
	}
	start := max(0, p-ctx)
	var sb strings.Builder
	fmt.Fprintf(&sb, "@@ -%d +%d @@\n", start+1, start+1)
	for i := start; i < p; i++ {
		sb.WriteString(" " + al[i] + "\n")
	}
	for i := p; i < len(al)-s; i++ {
		sb.WriteString("-" + al[i] + "\n")
	}
	for i := p; i < len(bl)-s; i++ {
		sb.WriteString("+" + bl[i] + "\n")
	}
	for i := len(al) - s; i < min(len(al), len(al)-s+ctx); i++ {
		sb.WriteString(" " + al[i] + "\n")
	}
	return sb.String()
}

// shellFsCmd builds simple mutating fs commands executed via the shell so
// that --sudo works uniformly.
func shellFsCmd(use, short string, minArgs int, build func(args []string, flags map[string]bool) string, boolFlags map[string]string) *cobra.Command {
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
			if strings.HasPrefix(use, "rm ") && !g.allowDangerous {
				for _, p := range args[1:] {
					if cp := path.Clean(p); cp == "/" || cp == "." || cp == "~" || strings.Count(cp, "/") <= 1 && strings.HasPrefix(cp, "/") {
						return out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "pass --allow-dangerous if truly intended",
							"refusing to remove top-level path %q", p)
					}
				}
			}
			command := build(args[1:], fl)
			return runOne(cmd.Context(), "fs."+strings.Fields(use)[0], args[0], command, sudo, true)
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
	return shellFsCmd("rm TARGET PATH...", "Remove remote files (--recursive for directories)", 2, func(a []string, f map[string]bool) string {
		flags := "-f"
		if f["recursive"] {
			flags = "-rf"
		}
		return "rm " + flags + " -- " + quoteAll(a)
	}, map[string]string{"recursive": "remove directories recursively"})
}

func fsMkdirCmd() *cobra.Command {
	return shellFsCmd("mkdir TARGET PATH...", "Create remote directories (always -p)", 2, func(a []string, _ map[string]bool) string {
		return "mkdir -p -- " + quoteAll(a)
	}, nil)
}

func fsMvCmd() *cobra.Command {
	return shellFsCmd("mv TARGET SRC DST", "Move/rename a remote path", 3, func(a []string, _ map[string]bool) string {
		return "mv -- " + quoteAll(a)
	}, nil)
}

func fsChmodCmd() *cobra.Command {
	return shellFsCmd("chmod TARGET MODE PATH...", "Change mode of remote paths", 3, func(a []string, f map[string]bool) string {
		r := ""
		if f["recursive"] {
			r = "-R "
		}
		return "chmod " + r + sshx.Q(a[0]) + " -- " + quoteAll(a[1:])
	}, map[string]string{"recursive": "recurse"})
}
