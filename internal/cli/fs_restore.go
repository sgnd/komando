package cli

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/pkg/sftp"
	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// fsRestoreCmd puts back the newest backup that fs write or fs replace
// --backup made of PATH. The current file is kept as a backup in turn, so
// a restore can itself be undone.
func fsRestoreCmd() *cobra.Command {
	var sudo bool
	var from string
	c := &cobra.Command{
		Use:   "restore TARGET PATH",
		Short: "Undo a file edit by putting back its backup copy",
		Long: `Puts back the newest backup of PATH that fs write or fs replace --backup
made (PATH.bak, or PATH.bak.<UTC time> when there are several). The file as
it is now is kept as a new backup first, so you can undo the restore too.
On a group (@web) each server puts back its own newest backup. Add --dry-run
to see the change without making it.`,
		Example: `  komando fs restore web1 /etc/nginx/nginx.conf --sudo --dry-run
  komando fs restore web1 /etc/nginx/nginx.conf --sudo
  komando fs restore @web /etc/nginx/nginx.conf --sudo --dry-run
  komando fs restore web1 /etc/nginx/nginx.conf --copy /etc/nginx/nginx.conf.bak --sudo`,
		Args: cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			hosts, err := resolveTargets(cl, st, args[0])
			if err != nil {
				return err
			}
			if w := windowsNames(hosts); len(w) > 0 {
				return out.Usage("fs restore does not work on Windows servers yet (%s); copy the backup back with `komando exec %s -- Copy-Item ...`", strings.Join(w, ", "), w[0])
			}
			if err := guard(cl, st, hosts, "", true); err != nil {
				return err
			}
			r := restoreEdit{cl: cl, path: args[1], from: from, sudo: sudo}
			data, err := runFsFleet(cl, cmd.Context(), st, "fs.restore", args[1], hosts, r.on)
			if !cl.flags.dryRun {
				for _, row := range data.Results {
					if row["changed"] == true {
						textNote(cl, "Put back %s on %s from %s.", row["path"], row["host"], row["from"])
					}
				}
			}
			return err
		}),
	}
	fsRestoreFlags(c, &sudo, &from)
	return c
}

// restoreEdit is one fs restore: the same path on every server.
type restoreEdit struct {
	cl         *call // the call it works for
	path, from string
	sudo       bool
}

// on puts back the backup on one server.
func (r restoreEdit) on(ctx context.Context, c *sshx.Client) (fsChange, error) {
	sc, err := sftpClient(c)
	if err != nil {
		return nil, err
	}
	defer sc.Close()
	p := expandRemote(sc, r.path)
	b := r.from
	if b == "" {
		if b, err = findBackup(r.cl, sc, p); err != nil {
			return nil, err
		}
	}
	old, trunc, err := readRemote(r.cl, ctx, c, sc, b, r.sudo, 64<<20)
	if err != nil {
		return nil, err
	}
	if trunc {
		return nil, out.Errf(out.ExitConflict, "FILE_TOO_LARGE", "copy it back with `komando exec TARGET -- cp BACKUP PATH`", "%s is larger than 64MiB, the most fs restore reads", b)
	}
	cur, _, cerr := readRemote(r.cl, ctx, c, sc, p, r.sudo, 64<<20)
	if cerr != nil && toErr(cerr).Code != "PATH_NOT_FOUND" {
		return nil, cerr
	}
	a, z := string(cur), string(old)
	if r.cl.out.Mask {
		a, z = r.cl.out.View(a).Text, r.cl.out.View(z).Text
	}
	res := fsChange{"path": p, "from": b, "diff": unifiedDiff(a, z, 3)}
	if r.cl.flags.dryRun {
		res["would_change"] = string(cur) != string(old)
		return res, nil
	}
	w, err := writeRemote(r.cl, ctx, c, sc, p, old, writeOpts{sudo: r.sudo, backup: cerr == nil})
	if err != nil {
		return nil, err
	}
	for k, v := range w {
		res[k] = v
	}
	delete(res, "sha256") // the backup may hold a value komando hides
	res["changed"] = true
	return res, nil
}

// findBackup is the newest backup of p next to it.
func findBackup(cl *call, sc *sftp.Client, p string) (string, error) {
	ents, err := sc.ReadDir(path.Dir(p))
	if err != nil {
		return "", fsErr(cl, path.Dir(p), err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	n := newestBackup(path.Base(p), names)
	if n == "" {
		return "", out.Errf(out.ExitNotFound, "BACKUP_NOT_FOUND", "komando keeps a backup only when you edit with --backup; give another copy with --copy PATH",
			"no backup of %s found (looked for %s.bak)", p, path.Base(p))
	}
	return path.Join(path.Dir(p), n), nil
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
func textNote(cl *call, format string, a ...any) {
	if cl.out.Format != "text" {
		return
	}
	fmt.Fprintln(cl.out.Err, out.SafeText(cl.out.Redact(fmt.Sprintf(format, a...))))
}

// undoNote is the line after fs write or fs replace --backup.
// printChange prints the result of a file change, then the undo line.
func printChange(cl *call, command, host string, res fsChange, sudo bool) {
	cl.out.Print(command, res, nil)
	undoNote(cl, host, res, sudo)
}

func undoNote(cl *call, host string, res fsChange, sudo bool) {
	if cl.flags.dryRun || res["backup"] == nil || res["changed"] != true {
		return
	}
	s := ""
	if sudo {
		s = " --sudo"
	}
	textNote(cl, "Changed %s on %s. To undo: komando fs restore %s %s%s", res["path"], host, host, argQ(fmt.Sprint(res["path"])), s)
}

// argQ quotes s for a shell only when it needs it, so a plain path reads plainly.
func argQ(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-+:@=,%") == "" {
		return s
	}
	return sshx.Q(s)
}

// fsRestoreFlags are fs restore's own flags.
func fsRestoreFlags(c *cobra.Command, sudo *bool, from *string) {
	c.Flags().BoolVarP(sudo, "sudo", "s", false, "read and write with sudo (for files root owns)")
	c.Flags().StringVar(from, "copy", "", "the backup copy to put back, a path on the server (default: the newest PATH.bak)")
}
