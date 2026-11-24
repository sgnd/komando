package execsession

import (
	"strconv"
	"strings"
)

// Retention is how long a finished session stays when nobody removes it.
const Retention = 7 * 24 * 60 * 60

// ownCheck refuses (ExitUnsafe) a path that is a link or not a folder of
// the login user, and exits ExitGone when it is not there.
const ownCheck = `ks_own() { if [ -L "$1" ]; then exit 90; fi; [ -e "$1" ] || exit 95; { [ -d "$1" ] && [ -O "$1" ]; } || exit 90; }; `

// RemoveScript is the shell text that deletes one finished session: the
// folder and the two above it must be the login user's and not links
// (ExitUnsafe), and the run must have ended (ExitNotRunning).
func RemoveScript(id string) (string, error) {
	if err := CheckID(id); err != nil {
		return "", err
	}
	return `r="$HOME/.komando"; s="$r/sessions"; d="$s/` + id + `"; ` + ownCheck +
		`ks_own "$r"; ks_own "$s"; ks_own "$d"; ` +
		`[ -f "$d/exit" ] || [ -f "$d/killed" ] || exit ` + strconv.Itoa(ExitNotRunning) + `; rm -rf "$d"`, nil
}

// SweepScript deletes every session folder whose run ended more than
// Retention ago by the server's own clock. It takes only folders right
// below ~/.komando/sessions whose name is a session ID, that are the login
// user's and not links; a running session is never swept. A sessions
// folder that is missing, a link or not the login user's: nothing is swept.
var SweepScript = `s="$HOME/.komando/sessions"; ` +
	`{ [ -d "$HOME/.komando" ] && [ ! -L "$HOME/.komando" ] && [ -O "$HOME/.komando" ] && [ -d "$s" ] && [ ! -L "$s" ] && [ -O "$s" ]; } || exit 0; ` +
	`now=$(date -u +%s); for d in "$s"/*; do n=${d##*/}; case "$n" in ` + idGlob() + `) ;; *) continue;; esac; ` +
	`[ ! -L "$d" ] && [ -d "$d" ] && [ -O "$d" ] || continue; { [ -f "$d/exit" ] || [ -f "$d/killed" ]; } || continue; ` +
	`t=$(head -c 16 "$d/started" 2>/dev/null | tr -d '\r\n'); case "$t" in ''|*[!0-9]*) continue;; esac; ` +
	`[ $((now - t)) -gt ` + strconv.Itoa(Retention) + ` ] || continue; rm -rf "$d"; done; exit 0`

// idGlob is a shell pattern that matches a session ID and nothing else.
func idGlob() string { return strings.Repeat("[a-z2-7]", 52) }
