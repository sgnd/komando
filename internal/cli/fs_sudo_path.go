package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// Reading and writing a file as root (--sudo) on a path other server users
// can touch. Root must not follow a link one of them made (an app's .env ->
// /etc/sudoers.d/x), and must not write into a folder one of them can
// change: between komando's look and root's write, that user could swap
// the file for such a link (sudoedit's rule).

// Exit codes of these scripts.
const (
	sudoExitLink   = 92 // a link on the way is not one komando follows as root
	sudoExitFolder = 93 // the folder can be changed by another user
)

// sudoFolderMark starts the stderr line that names the folder and who can
// change it: "\036komando-folder WHO OWNER GROUP FOLDER".
const sudoFolderMark = "\036komando-folder "

// sudoWalkScript sets $p to its real path, one name at a time, as root.
// A link whose owner's uid is not in $ok (a space-separated list) runs
// stop. $f is 1 when a link was followed. A name that does not exist yet
// stays as it is (a new file, or folders -p makes).
func sudoWalkScript(stop string) string {
	return `f=; r=; i=0; case $p in /*) s=${p#/};; *) s=$(pwd -P)/$p; s=${s#/};; esac; ` +
		`while [ -n "$s" ]; do c=${s%%/*}; case $s in */*) s=${s#*/};; *) s=;; esac; ` +
		`case $c in ''|.) continue;; ..) r=${r%/*}; continue;; esac; x=$r/$c; ` +
		`if [ -L "$x" ]; then case " $ok " in *" $(stat -c %u -- "$x") "*) ;; *) ` + stop + `;; esac; ` +
		`f=1; i=$((i+1)); [ "$i" -lt 40 ] || ` + stop + `; t=$(readlink -- "$x"); ` +
		`case $t in /*) r=;; esac; s=$t${s:+/$s}; else r=$x; fi; done; p=${r:-/}; `
}

// sudoFolderScript stops with exit 93 when the folder $p goes into, or a
// folder above it, can be changed by a user other than root and the SSH
// user ($me): owned by another user, writable by a group other than
// root's, writable by everyone, or writable by a user or group its
// access list (POSIX ACL) names. A folder above with the sticky bit
// (/tmp) is fine: no one can move the folder under it that root or $me
// owns. The folder itself never is: anyone could make the file first.
// Without getfacl, any access list (a mode ending in + in ls -l) stops.
func sudoFolderScript(tmpQ string) string {
	return `d=$(dirname -- "$p"); while [ ! -e "$d" ]; do d=$(dirname -- "$d"); done; c=; ` +
		`while :; do set -- $(stat -c '%u %g %a' -- "$d"); w=; ` +
		`case $1 in 0|"$me") ;; *) w=user;; esac; ` +
		`if [ "$2" != 0 ] && [ $((0$3 & 020)) != 0 ]; then w=group; fi; ` +
		`if [ $((0$3 & 02)) != 0 ] && { [ -z "$c" ] || [ $((0$3 & 01000)) = 0 ]; }; then w=everyone; fi; ` +
		`if [ -z "$w" ] && { [ -z "$c" ] || [ $((0$3 & 01000)) = 0 ]; }; then ` +
		`if command -v getfacl >/dev/null 2>&1; then ` +
		`getfacl -cn -- "$d" 2>/dev/null | grep -E '^(user|group):[0-9]+:.w' | grep -Ev "^(user:($me|0)|group:0):" | grep -q . && w=acl; ` +
		`else case $(ls -ld -- "$d") in ??????????+*) w=acl;; esac; fi; fi; ` +
		`if [ -n "$w" ]; then printf '\036komando-folder %s %s %s\n' "$w" "$(stat -c '%U %G' -- "$d")" "$d" >&2; rm -f ` + tmpQ + `; exit 93; fi; ` +
		`[ "$d" = / ] && break; c=1; d=$(dirname -- "$d"); done; `
}

// sudoWriteScript checks $p before root writes it, and sets $p to the
// file root writes. With noFollow a link at $p stops with exit 95. Only
// root's links are followed (exit 92 for any other), and only into a
// folder root owns (for a folder --mkdirs makes, the nearest one there);
// the folder rule is sudoFolderScript. The SSH user's own links are not
// followed either, unlike for a read: komando's rules look at the path
// given, and a link the agent made as that user would move a write as
// root somewhere else.
func sudoWriteScript(tmpQ string, noFollow bool) string {
	stop := "{ rm -f " + tmpQ + "; exit 92; }"
	var sb strings.Builder
	sb.WriteString(`me=${SUDO_UID:-0}; ok=0; `)
	if noFollow {
		sb.WriteString(`if [ -L "$p" ]; then rm -f ` + tmpQ + `; exit 95; fi; `)
	}
	sb.WriteString(sudoWalkScript(stop))
	// the folder the link led into, or (--mkdirs) the nearest one there
	sb.WriteString(`if [ "$f" = 1 ]; then d=$(dirname -- "$p"); while [ ! -e "$d" ]; do d=$(dirname -- "$d"); done; ` +
		`[ "$(stat -c %u -- "$d")" = 0 ] || ` + stop + `; fi; `)
	sb.WriteString(sudoFolderScript(tmpQ))
	return sb.String()
}

// sudoReadScript reads p as root with reader (cat, tail -c N) on stdin. A
// link made by a user other than root and the SSH user is not followed
// (exit 92). The file is opened from inside its folder, and read only
// when what was opened is the file that is there by that name: a link
// put in its place, or a folder swapped on the way, in between is refused.
func sudoReadScript(p, reader string) string {
	return `p=` + sshx.Q(p) + `; me=${SUDO_UID:-0}; ok="0 $me"; ` + sudoWalkScript("exit 92") +
		`d=$(dirname -- "$p"); n=$(basename -- "$p"); nf() { printf '%s: No such file or directory\n' "$p" >&2; exit 1; }; ` +
		`cd -- "$d" 2>/dev/null || nf; [ "$(pwd -P)" = "$d" ] || exit 92; ` +
		`[ -e "./$n" ] || nf; exec 3< "./$n"; ` +
		`if [ -L "./$n" ] || [ "$(stat -L -c %d:%i /dev/fd/3)" != "$(stat -c %d:%i -- "./$n")" ]; then exit 92; fi; ` +
		reader + ` <&3`
}

// unsafeFolder is exit 93 of a write as root: stderr names the folder and
// who can change it.
func unsafeFolder(p, stderr string) error {
	who, owner, group, dir := "", "", "", p
	for _, l := range strings.Split(stderr, "\n") {
		if _, rest, ok := strings.Cut(l, sudoFolderMark); ok {
			if f := strings.SplitN(rest, " ", 4); len(f) == 4 {
				who, owner, group, dir = f[0], f[1], f[2], f[3]
			}
		}
	}
	by, as := "user "+owner, owner
	switch who {
	case "group":
		by, as = "the group "+group, "a user of the group "+group
	case "everyone":
		by, as = "every user", "the user who should own the file"
	case "acl":
		by, as = "a user or group its access list (ACL) names", "the user who should own the file"
	}
	user := "USER"
	if who == "user" && owner != "" {
		user = owner
	}
	return out.Errf(out.ExitConflict, "SHARED_FOLDER_CONFLICT",
		"write it as "+as+" instead, for example `komando exec TARGET --sudo-user "+user+" --stdin-file FILE -- sh -c 'cat > \"$0\"' "+sshx.Q(p)+"`",
		"%s can be changed by %s, not only by root and the SSH user: as root, komando does not write %s there (that user could swap it for a link while root writes)", dir, by, p)
}

// writeRemoteSudo is writeRemoteFrom with --sudo: the content is staged in
// the SSH user's /tmp (0600), then root checks the path and installs it.
func writeRemoteSudo(cl *call, ctx context.Context, c *sshx.Client, sc *sftp.Client, p, mode, tmpName string, o writeOpts, res map[string]any, copyIn func(io.Writer) error) (map[string]any, error) {
	tmp := path.Join("/tmp", tmpName)
	f, err := sc.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return nil, fsErr(cl, tmp, err)
	}
	// only the SSH user may read the staged content (it can be a secret)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		sc.Remove(tmp)
		return nil, fsErr(cl, tmp, err)
	}
	if err := copyIn(f); err != nil {
		f.Close()
		sc.Remove(tmp)
		return nil, err
	}
	f.Close()
	r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: sudoInstallScript(p, mode, tmp, o), Sudo: true, Timeout: time.Minute, MaxOutput: 64 << 10})
	if err != nil {
		_ = sc.Remove(tmp)
		return nil, err
	}
	switch {
	case r.ExitCode == 97 && o.validate != "":
		return nil, validateFailed(r.Stderr)
	case r.ExitCode == 95:
		return nil, linkStop(p, o.noFollow)
	case r.ExitCode == sudoExitLink:
		return nil, notRootsLink(p)
	case r.ExitCode == sudoExitFolder:
		return nil, unsafeFolder(p, r.Stderr)
	case r.ExitCode == 94 && o.backup:
		return nil, backupFailed(p, r.Stderr)
	case r.ExitCode == 96:
		return nil, folderMissing(path.Dir(p))
	case r.ExitCode != 0:
		_ = sc.Remove(tmp)
		return nil, out.Errf(out.ExitRemote, "WRITE_FAILED", "check that the folder is writable and has free space: `komando exec TARGET --read-only -- df -h`", "%s", strings.TrimSpace(r.Stderr))
	}
	res["mode"] = sudoInstallResult(r.Stdout, mode, o, res)
	return res, nil
}

// sudoInstallResult reads the line sudoInstallScript prints ("MODE
// REPLACED BACKUP-SUFFIX FOLLOWED PATH") into res and returns the mode.
// followed is set only when a link was followed: the walk always turns
// the path into its real one, so a relative or non-canonical path
// (notes.txt, /etc//app/x) differs from it with no link involved.
func sudoInstallResult(stdout, mode string, o writeOpts, res map[string]any) string {
	f := strings.SplitN(strings.TrimSpace(stdout), " ", 5)
	if len(f) != 5 {
		return mode
	}
	res["replaced"] = f[1] == "1"
	if f[3] == "1" {
		res["followed"] = f[4]
	}
	if o.backup && f[2] != "-" {
		res["backup"] = f[4] + "." + f[2]
	}
	return fmt.Sprintf("%04s", f[0])
}

// sudoInstallScript is the root side of writeRemoteSudo.
func sudoInstallScript(p, mode, tmp string, o writeOpts) string {
	var sb strings.Builder
	sb.WriteString("set -e; p=" + sshx.Q(p) + "; ")
	// a symlink (sites-enabled -> sites-available): write the file it
	// names, so the link stays a link
	sb.WriteString(sudoWriteScript(sshx.Q(tmp), o.noFollow))
	if o.mkdirs {
		sb.WriteString(`mkdir -p "$(dirname -- "$p")"; `)
	} else {
		sb.WriteString(`if [ ! -d "$(dirname -- "$p")" ]; then rm -f ` + sshx.Q(tmp) + `; exit 96; fi; `)
	}
	// keep the mode of the existing file; read it as root, because the SSH
	// user often cannot see into the directory (/etc/sudoers.d, /root)
	if mode == "" {
		sb.WriteString(`m=$(stat -c %a "$p" 2>/dev/null || echo ` + cmp.Or(o.newMode, "644") + `); `)
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
	if o.owner == "" {
		sb.WriteString(`o=$(stat -c %u:%g "$p" 2>/dev/null || echo 0:0); `)
		sb.WriteString(`install -m "$m" -o "${o%:*}" -g "${o#*:}" ` + sshx.Q(tmp) + ` "$p"; `)
	} else {
		u, gr, _ := strings.Cut(o.owner, ":")
		sb.WriteString(`install -m "$m" -o ` + sshx.Q(u))
		if gr != "" {
			sb.WriteString(" -g " + sshx.Q(gr))
		}
		sb.WriteString(" " + sshx.Q(tmp) + ` "$p"; `)
	}
	sb.WriteString("rm -f " + sshx.Q(tmp) + `; printf '%s %s %s %s %s\n' "$m" "$r" "$k" "${f:-0}" "$p"`)
	return sb.String()
}
