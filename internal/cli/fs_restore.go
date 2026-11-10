package cli

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// fsRestoreCmd puts back the newest backup that fs write or fs replace
// --backup made of PATH. The current file is kept as a backup in turn, so
// a restore can itself be undone.
func fsRestoreCmd() *cobra.Command {
	var sudo bool
	var from string
	c := &cobra.Command{
		Use:   "restore TARGET PATH",
		Short: "Undo a file edit: put back the copy --backup kept (PATH.bak)",
		Long: `Puts back the newest backup of PATH that fs write or fs replace --backup
made (PATH.bak, or PATH.bak.<UTC time> when there are several). The file as
it is now is kept as a new backup first, so you can undo the restore too.
Add --dry-run to see the change without making it.`,
		Example: `  komando fs restore web1 /etc/nginx/nginx.conf --sudo --dry-run
  komando fs restore web1 /etc/nginx/nginx.conf --sudo
  komando fs restore web1 /etc/nginx/nginx.conf --from /etc/nginx/nginx.conf.bak --sudo`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			h, err := oneServer(st, args[0], "fs restore puts back one server's file; run it per server")
			if err != nil {
				return err
			}
			if h.Windows() {
				return out.Usage("fs restore does not work on Windows servers yet; copy the backup back with `komando exec %s -- Copy-Item ...`", h.Name)
			}
			if err := guard(st, []*store.Host{h}, "", true); err != nil {
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
				b := from
				if b == "" {
					ents, err := sc.ReadDir(path.Dir(p))
					if err != nil {
						return fsErr(path.Dir(p), err)
					}
					names := make([]string, 0, len(ents))
					for _, e := range ents {
						names = append(names, e.Name())
					}
					n := newestBackup(path.Base(p), names)
					if n == "" {
						return out.Errf(out.ExitNotFound, "BACKUP_NOT_FOUND", "komando keeps a backup only when you edit with --backup; give another copy with --from FILE",
							"no backup of %s found (looked for %s.bak)", p, path.Base(p))
					}
					b = path.Join(path.Dir(p), n)
				}
				old, trunc, err := readRemote(cmd.Context(), c, sc, b, sudo, 64<<20)
				if err != nil {
					return err
				}
				if trunc {
					return out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "copy it back with `komando exec TARGET -- cp BACKUP PATH`", "%s is larger than 64MiB, the most fs restore reads", b)
				}
				cur, _, cerr := readRemote(cmd.Context(), c, sc, p, sudo, 64<<20)
				if cerr != nil && toErr(cerr).Code != "PATH_NOT_FOUND" {
					return cerr
				}
				a, z := string(cur), string(old)
				if out.P.Mask {
					a, z = out.P.View(a).Text, out.P.View(z).Text
				}
				res = fsChange{"path": p, "from": b, "diff": unifiedDiff(a, z, 3)}
				if g.dryRun {
					res["would_change"] = string(cur) != string(old)
					return nil
				}
				w, err := writeRemote(cmd.Context(), c, sc, p, old, writeOpts{sudo: sudo, backup: cerr == nil})
				if err != nil {
					return err
				}
				for k, v := range w {
					res[k] = v
				}
				delete(res, "sha256") // the backup may hold a value komando hides
				res["changed"] = true
				return nil
			})
			audit(st, "fs.restore", []string{h.Name}, "", err == nil, map[string]any{"path": args[1]})
			if err != nil {
				return err
			}
			out.P.Print("fs.restore", res, nil)
			if !g.dryRun {
				textNote("Put back %s on %s from %s.", res["path"], h.Name, res["from"])
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&sudo, "sudo", "s", false, "read and write with sudo (for files root owns)")
	c.Flags().StringVar(&from, "from", "", "the backup to put back (default: the newest PATH.bak)")
	return c
}

// newestBackup picks the newest backup of base among names: the
// base.bak.<UTC time>[-N] names sort by time, and base.bak is the oldest.
func newestBackup(base string, names []string) string {
	var stamped []string
	plain := ""
	for _, n := range names {
		switch {
		case n == base+".bak":
			plain = n
		case strings.HasPrefix(n, base+".bak.") && len(n) > len(base)+5:
			stamped = append(stamped, n)
		}
	}
	if len(stamped) == 0 {
		return plain
	}
	sort.Slice(stamped, func(i, j int) bool { return backupKey(stamped[i]) < backupKey(stamped[j]) })
	return stamped[len(stamped)-1]
}

// backupKey makes "x.bak.<time>-10" sort after "x.bak.<time>-9".
func backupKey(n string) string {
	if i := strings.LastIndex(n, "-"); i > 0 && i > strings.LastIndex(n, ".") {
		return fmt.Sprintf("%s-%06s", n[:i], n[i+1:])
	}
	return n + "-000000"
}

// textNote prints one line for a person after a command's output (text
// mode only, on stderr): JSON output and pipes stay the same.
func textNote(format string, a ...any) {
	if out.P.Format != "text" {
		return
	}
	fmt.Fprintln(os.Stderr, out.SafeText(out.P.Redact(fmt.Sprintf(format, a...))))
}

// undoNote is the line after fs write or fs replace --backup.
// printChange prints the result of a file change, then the undo line.
func printChange(command, host string, res fsChange, sudo bool) {
	out.P.Print(command, res, nil)
	undoNote(host, res, sudo)
}

func undoNote(host string, res fsChange, sudo bool) {
	if g.dryRun || res["backup"] == nil || res["changed"] != true {
		return
	}
	s := ""
	if sudo {
		s = " --sudo"
	}
	textNote("Changed %s on %s. To undo: komando fs restore %s %s%s", res["path"], host, host, argQ(fmt.Sprint(res["path"])), s)
}

// argQ quotes s for a shell only when it needs it, so a plain path reads plainly.
func argQ(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-+:@=,%") == "" {
		return s
	}
	return sshx.Q(s)
}
