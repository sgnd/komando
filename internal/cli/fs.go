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
	"strings"
	"time"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

func fsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "fs",
		Short: "Files on servers: ls, cat, write, replace, rm, mkdir, mv, chmod",
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
					w := storex.SortedWalk(sc, dir)
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
					fis, err := storex.SortedReadDir(sc, dir)
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
	return out.Errf(out.ExitUsage, "IS_A_DIRECTORY", "list it with `komando fs ls TARGET "+p+"`", "%s is a folder, not a file", p)
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
			if strings.HasPrefix(use, "rm ") && fl["recursive"] && !dangerOK() && !confirmDangerous(args[:1], "rm --recursive deletes whole folders and everything in them") {
				if err := policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "a folder and everything in it would be gone; confirm with the user, then add --allow-dangerous",
					"rm --recursive deletes whole folders")); err != nil {
					return err
				}
			}
			if strings.HasPrefix(use, "rm ") {
				for _, p := range args[1:] {
					if cp := path.Clean(p); (cp == "/" || cp == "." || cp == "~" || strings.Count(cp, "/") <= 1 && strings.HasPrefix(cp, "/")) && !dangerOK() &&
						!confirmDangerous(args[:1], fmt.Sprintf("removing the top-level path %s", p)) {
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
	c := shellFsCmd("rm TARGET PATH...", "Remove remote files (--recursive for folders; missing ones are reported)", 2, func(a []string, f map[string]bool) (string, string, error) {
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
