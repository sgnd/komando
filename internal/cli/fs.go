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

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/storex"
)

func fsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "fs",
		Short: "Files on servers: read, edit, undo an edit, move, remove",
		Long: `Reads and changes files on servers over SFTP and returns structured
results. Use --sudo for files that root owns: a read runs ` + "`sudo cat`" + `, a write
goes to a temporary file first and then into place with ` + "`sudo install`" + `.

For an agent, ` + "`fs replace`" + ` is the way to edit a config file: it fails unless the
old text matches exactly once (or --all), and --backup keeps a .bak copy.`,
	}
	c.AddCommand(fsLsCmd(), fsStatCmd(), fsCatCmd(), fsWriteCmd(), fsReplaceCmd(), fsRmCmd(), fsMkdirCmd(), fsMvCmd(), fsChmodCmd(), fsRestoreCmd())
	for _, sub := range c.Commands() {
		if run := sub.RunE; run != nil && sub.Flags().Lookup("sudo") != nil {
			sub.RunE = func(cmd *cobra.Command, args []string) error {
				fsSudoRetry = sudoRetryHint(cmd, args)
				return run(cmd, args)
			}
		}
	}
	return c
}

// fsSudoRetry is the hint of a permission error in the fs command running
// now: the same command line with --sudo, to copy.
var fsSudoRetry = "retry with --sudo"

// sudoRetryHint is "retry with --sudo: `komando fs ... --sudo`", the
// command as given plus --sudo. Approval flags are never in it; a long
// --content (or one already with --sudo) keeps the short hint.
func sudoRetryHint(cmd *cobra.Command, args []string) string {
	const short = "retry with --sudo"
	if on, _ := cmd.Flags().GetBool("sudo"); on {
		return "it was refused even with --sudo (a read-only mount, or a protected file): `komando fs stat` shows its owner and mode"
	}
	parts := append(strings.Fields(cmd.CommandPath()), args...)
	long := false
	cmd.Flags().Visit(func(f *pflag.Flag) {
		switch f.Name {
		case "yes", "allow-dangerous", "reveal", "output":
			return
		}
		v := f.Value.String()
		if len(v) > 120 || strings.ContainsAny(v, "\n\r") {
			long = true
			return
		}
		if f.Value.Type() == "bool" {
			if v == "true" {
				parts = append(parts, "--"+f.Name)
			}
			return
		}
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			for _, one := range sv.GetSlice() {
				parts = append(parts, "--"+f.Name, one)
			}
			return
		}
		parts = append(parts, "--"+f.Name, v)
	})
	if long {
		return short
	}
	return short + ": `" + shellLine(append(parts, "--sudo")) + "`"
}

func sftpClient(c *sshx.Client) (*sftp.Client, error) {
	s, err := sftp.NewClient(c.Client)
	if err != nil {
		return nil, out.Errf(out.ExitConnect, "SFTP_UNAVAILABLE", "enable the sftp subsystem in sshd_config", "sftp: %v", err)
	}
	return s, nil
}

// oneHost resolves target, dials it and runs fn with both ssh and sftp.
func oneHost(ctx context.Context, target string, fn func(st *store.State, c *sshx.Client, sc *sftp.Client) (any, error)) (any, error) {
	st, err := loadState()
	if err != nil {
		return nil, err
	}
	h, err := singleHost(st, target)
	if err != nil {
		return nil, err
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
	return res, err
}

func fsErr(p string, err error) error {
	return fsErrHint(p, err, fsSudoRetry)
}

// fsErrHint is fsErr for commands without --sudo: permHint says what to do
// about a permission problem instead.
func fsErrHint(p string, err error, permHint string) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return out.Errf(out.ExitNotFound, "PATH_NOT_FOUND", "list the folder with `komando fs list TARGET "+path.Dir(p)+"`", "%s: no such file or directory", p)
	case errors.Is(err, os.ErrPermission):
		return out.Errf(out.ExitRemote, "PERMISSION_DENIED", permHint, "%s: permission denied", p)
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
		Use:   "list SERVER [PATH]",
		Short: "List a folder on one server (default: the login user's home)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			arg := ""
			if len(args) == 2 {
				arg = args[1]
			}
			if st, h := windowsOne(args[0]); h != nil {
				return printed("fs.ls")(winFsLs(cmd.Context(), st, h, arg, all, recursive, maxEntries))
			}
			res, err := oneHost(cmd.Context(), args[0], func(_ *store.State, _ *sshx.Client, sc *sftp.Client) (any, error) {
				dir := expandRemote(sc, arg)
				permHint := "fs list reads as the SSH user; list it as root with `komando exec " + args[0] + " --sudo -- ls -la " + sshx.Q(dir) + "`"
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
						if maxEntries > 0 && len(r.Entries) >= maxEntries {
							r.Truncated = true
							out.P.CutNoted()
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
						if maxEntries > 0 && len(r.Entries) >= maxEntries {
							r.Truncated = true
							out.P.CutNoted()
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
	c.Flags().BoolVarP(&recursive, "recursive", "r", false, "list the folders inside too")
	limitFlag(c, &maxEntries, 1000, "entries")
	retiredFlag(c, "max", "limit")
	withID(c, "fs.ls") // `ls` before: a permanent synonym
	return c
}

func fsStatCmd() *cobra.Command {
	var hash bool
	c := &cobra.Command{
		Use:   "stat SERVER PATH",
		Short: "Look up a path on one server (exists:false, not an error, when missing)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if st, h := windowsOne(args[0]); h != nil {
				return printed("fs.stat")(winFsStat(cmd.Context(), st, h, args[1], hash))
			}
			res, err := oneHost(cmd.Context(), args[0], func(_ *store.State, _ *sshx.Client, sc *sftp.Client) (any, error) {
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
		r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: sudoReadScript(p, "cat"), Sudo: true, MaxOutput: int(limit), Timeout: 2 * time.Minute})
		if err != nil {
			return nil, false, err
		}
		if r.ExitCode == sudoExitLink {
			return nil, false, readLinkStop(p)
		}
		if r.ExitCode != 0 {
			if strings.Contains(r.Stderr, "No such file") {
				return nil, false, fsErr(p, os.ErrNotExist)
			}
			if strings.Contains(r.Stderr, "Is a directory") {
				return nil, false, isADirectory(p)
			}
			return nil, false, out.Errf(out.ExitRemote, "READ_FAILED", "check the path and its permissions with `komando fs stat SERVER PATH`, or add --sudo", "%s", strings.TrimSpace(r.Stderr))
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

// readRemoteEnd is readRemote for the end of the file (fs cat --tail): the
// last limit bytes. When the file is longer, the first line read is cut
// short, so it is left out, and trunc is true.
func readRemoteEnd(ctx context.Context, c *sshx.Client, sc *sftp.Client, p string, sudo bool, limit int64) ([]byte, bool, error) {
	var b []byte
	if sudo {
		r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: sudoReadScript(p, "tail -c "+strconv.FormatInt(limit+1, 10)), Sudo: true, MaxOutput: int(limit + 1), Timeout: 2 * time.Minute})
		if err != nil {
			return nil, false, err
		}
		if r.ExitCode == sudoExitLink {
			return nil, false, readLinkStop(p)
		}
		if r.ExitCode != 0 {
			if strings.Contains(r.Stderr, "No such file") {
				return nil, false, fsErr(p, os.ErrNotExist)
			}
			if strings.Contains(r.Stderr, "Is a directory") {
				return nil, false, isADirectory(p)
			}
			return nil, false, out.Errf(out.ExitRemote, "READ_FAILED", "check the path and its permissions with `komando fs stat SERVER PATH`, or add --sudo", "%s", strings.TrimSpace(r.Stderr))
		}
		b = []byte(r.Stdout)
	} else {
		fi, err := sc.Stat(p)
		if err != nil {
			return nil, false, fsErr(p, err)
		}
		if fi.IsDir() {
			return nil, false, isADirectory(p)
		}
		f, err := sc.Open(p)
		if err != nil {
			return nil, false, fsErr(p, err)
		}
		defer f.Close()
		if from := fi.Size() - limit - 1; from > 0 {
			if _, err := f.Seek(from, io.SeekStart); err != nil {
				return nil, false, fsErr(p, err)
			}
		}
		if b, err = io.ReadAll(io.LimitReader(f, limit+1)); err != nil {
			return nil, false, fsErr(p, err)
		}
	}
	if int64(len(b)) <= limit {
		return b, false, nil
	}
	b = b[1:]
	if i := bytes.IndexByte(b, '\n'); i >= 0 && i < len(b)-1 {
		b = b[i+1:]
	}
	return b, true, nil
}

func isADirectory(p string) error {
	return out.Errf(out.ExitUsage, "IS_A_DIRECTORY", "list it with `komando fs list TARGET "+p+"`", "%s is a folder, not a file", p)
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
		Use:     "cat SERVER PATH",
		Aliases: []string{"read"},
		Short:   "Read a file on one server",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if maxBytes <= 0 {
				return out.Usage("--max-bytes must be more than 0")
			}
			var res any
			var err error
			if st, h := windowsOne(args[0]); h != nil {
				res, err = winFsCat(cmd.Context(), st, h, args[1], sudo, maxBytes, head, tail, numbered)
			} else {
				res, err = oneHost(cmd.Context(), args[0], func(_ *store.State, c *sshx.Client, sc *sftp.Client) (any, error) {
					p := expandRemote(sc, args[1])
					read, fromEnd := readRemote, tail > 0 && head == 0
					if fromEnd {
						read = readRemoteEnd
					}
					b, trunc, err := read(cmd.Context(), c, sc, p, sudo, maxBytes)
					if err != nil {
						return nil, err
					}
					// where the last lines of a long file start is not known
					num := numbered && !(fromEnd && trunc)
					r, err := catContent(args[0], p, b, trunc, head, tail, num)
					if num != numbered {
						r.Note = strings.TrimSpace(r.Note + " The file is larger than --max-bytes, so these last lines have no line numbers; raise --max-bytes to number them.")
					}
					return r, err
				})
			}
			if err != nil {
				return err
			}
			out.P.Print("fs.cat", res, nil)
			if r, ok := res.(catResult); ok && r.Truncated && out.P.Format == "text" {
				fmt.Fprintf(os.Stderr, "Note: showing the first %s; raise --max-bytes, or use `komando download`\n", humanBytes(maxBytes))
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&sudo, "sudo", "s", false, "read with sudo")
	maxBytes = 1 << 20
	c.Flags().Var(&bytesFlag{n: &maxBytes}, "max-bytes", "the most bytes to read, e.g. 4MiB")
	c.Flags().IntVar(&head, "head", 0, "only the first N lines")
	c.Flags().IntVar(&tail, "tail", 0, "only the last N lines")
	c.Flags().BoolVar(&numbered, "line-numbers", false, "start each line with its number")
	return c
}

// catContent is fs cat's result for the file p of target, read as b. A
// --tail of b counts as the file's end only when b was read from the end
// (readRemoteEnd) or is the whole file.
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
			if strings.HasPrefix(use, "rm ") && len(args) > 1 {
				if err := guardFsRm(args[0], args[1:], fl["recursive"]); err != nil {
					return err
				}
			}
			script, shown, err := build(args[1:], fl)
			if err != nil {
				return err
			}
			return runFleet(cmd.Context(), "fs."+strings.Fields(use)[0], args[0], script, nil, execOpts{sudo: sudo, display: shown, exitMap: func(rr *sshx.RunResult) *out.Error { return fsExitMap(rr.ExitCode, rr.Stderr) }}, true)
		},
	}
	c.Flags().BoolVarP(&sudo, "sudo", "s", false, "run with sudo")
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
	c := shellFsCmd("rm TARGET PATH...", "Remove files on servers", 2, func(a []string, f map[string]bool) (string, string, error) {
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
	c := shellFsCmd("mkdir TARGET PATH...", "Create folders on servers, with any missing parents", 2, func(a []string, _ map[string]bool) (string, string, error) {
		return mkdirScript(a), "mkdir -p -- " + rqAll(a), nil
	}, nil)
	// it always makes the parents; -p, typed from habit, changes nothing
	c.Flags().BoolP("parents", "p", false, "make missing parents (always done)")
	_ = c.Flags().MarkHidden("parents")
	return c
}

func fsMvCmd() *cobra.Command {
	c := shellFsCmd("mv TARGET SRC DST", "Move or rename a path on servers", 3, func(a []string, f map[string]bool) (string, string, error) {
		if len(a) != 2 {
			return "", "", out.Usage("give one SRC and one DST: komando fs mv TARGET SRC DST")
		}
		// -n: an existing file stops the move (FILE_EXISTS); -f replaces it
		flag := "-n"
		if f["overwrite"] {
			flag = "-f"
		}
		return mvScript(a[0], a[1], f["overwrite"]), "mv " + flag + " -- " + rqAll(a), nil
	}, map[string]string{"overwrite": "replace DST if it exists"})
	c.Long = `Moves SRC to DST. When DST is an existing folder, SRC moves into it (like mv).
An existing file at the destination is never replaced unless --overwrite
(FILE_EXISTS, exit 8).`
	return c
}

func fsChmodCmd() *cobra.Command {
	return shellFsCmd("chmod TARGET MODE PATH...", "Change the mode of paths on servers", 3, func(a []string, f map[string]bool) (string, string, error) {
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
	}, map[string]string{"recursive": "change folders and everything in them"})
}

func checkValidate(v string) error {
	if v != "" && !strings.Contains(v, "%s") {
		return out.Usage("--validate needs %%s where the new file's path goes, for example --validate 'visudo -cf %%s'")
	}
	return nil
}
