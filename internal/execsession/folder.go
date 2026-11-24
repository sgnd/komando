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
// of the login user, not links, and are made private; the session folder
// is made new (mkdir without -p), never found. Never /tmp.
func FolderScript(id string) (string, error) {
	if err := CheckID(id); err != nil {
		return "", err
	}
	return `umask 077; [ -n "$HOME" ] || exit 91; ` +
		`r="$HOME/.komando"; s="$r/sessions"; d="$s/` + id + `"; ` +
		`ks_dir() { if [ -L "$1" ]; then return 90; fi; ` +
		`if [ -e "$1" ]; then { [ -d "$1" ] && [ -O "$1" ]; } || return 90; ` +
		`else mkdir "$1" 2>/dev/null || return 91; fi; chmod 700 "$1" 2>/dev/null || return 91; }; ` +
		`ks_dir "$r" || exit $?; ks_dir "$s" || exit $?; ` +
		`if [ -e "$d" ] || [ -L "$d" ]; then exit 90; fi; mkdir "$d" 2>/dev/null || exit 91`, nil
}
