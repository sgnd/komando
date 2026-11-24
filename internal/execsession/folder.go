package execsession

// Exit codes of the folder prelude, apart from any a command gives:
// ExitUnsafe refuses the start (a link, a file, a folder not the login
// user's, or a session folder that already exists); ExitNoFolder means no
// folder can be made there (a read-only or full home), and exec runs the
// command without a session.
const (
	ExitUnsafe   = 90
	ExitNoFolder = 91
)

// Root is the folder that holds the sessions, below the login user's home.
const Root = ".komando/sessions"

// FolderScript is the shell text that makes the session folder and sets
// $d to it: umask 077; ~/.komando and its sessions folder must be folders
// of the login user, not links. One that others can write is refused
// (someone may have put anything there); one others can only read is
// made private, with a "warning" line, since earlier logs may have been
// read. The session folder is made new (mkdir without -p). Never /tmp.
func FolderScript(id string) (string, error) {
	if err := CheckID(id); err != nil {
		return "", err
	}
	return `umask 077; [ -n "$HOME" ] || exit 91; ` +
		`r="$HOME/.komando"; s="$r/sessions"; d="$s/` + id + `"; ` +
		`ks_dir() { if [ -L "$1" ]; then return 90; fi; ` +
		`if [ ! -e "$1" ]; then mkdir "$1" 2>/dev/null || return 91; return 0; fi; ` +
		`{ [ -d "$1" ] && [ -O "$1" ]; } || return 90; ` +
		`o=$(find "$1" -prune \( -perm -g=w -o -perm -o=w \) -print) || return 90; [ -z "$o" ] || return 90; ` +
		`o=$(find "$1" -prune \( -perm -g=r -o -perm -o=r -o -perm -g=x -o -perm -o=x \) -print) || return 90; [ -n "$o" ] || return 0; ` +
		`m=$(stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null); chmod 700 "$1" 2>/dev/null || return 91; ` +
		`echo "warning $2 was mode $m; now 700; earlier logs may have been read"; }; ` +
		`ks_dir "$r" '~/.komando' || exit $?; ks_dir "$s" '~/.komando/sessions' || exit $?; ` +
		`if [ -e "$d" ] || [ -L "$d" ]; then exit 90; fi; mkdir "$d" 2>/dev/null || exit 91`, nil
}
