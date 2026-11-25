package execsession

import (
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Retention is how long a finished session stays when nobody removes it.
const Retention = 7 * 24 * 60 * 60

// ownCheck refuses (ExitUnsafe) a path that is a link or not a folder of
// the login user, and exits ExitGone when it is not there.
const ownCheck = `ks_own() { if [ -L "$1" ]; then exit 90; fi; [ -e "$1" ] || exit 95; { [ -d "$1" ] && [ -O "$1" ]; } || exit 90; }; `

// ended is true in shell when the run in $d is over: it wrote exit, was
// stopped (killed), or was found lost.
const ended = `{ [ -f "$d/exit" ] || [ -f "$d/killed" ] || [ -f "$d/lost" ]; }`

// lostCheck is true in shell when rec's process, by the PID and start in
// the record on this computer, is no longer the live one: the run's root
// died without writing exit or killed (a reboot, an OOM kill). Never the
// pid file on the server: the running command owns it. A record that
// is not id's, or has no usable PID or start, never counts as lost.
func lostCheck(id string, rec *store.ExecSession) string {
	if rec == nil || rec.ID != id || rec.PID <= 1 || rec.ProcStart == "" {
		return "false"
	}
	return `[ "$(ks_start ` + strconv.Itoa(rec.PID) + `)" != ` + sshx.Q(rec.ProcStart) + ` ]`
}

// markLost writes the lost mark; with noclobber it is never written
// through a link the run left there.
const markLost = `(set -C; : > "$d/lost") 2>/dev/null; `

// RemoveScript is the shell text that deletes one finished session: the
// folder and the two above it must be the login user's and not links
// (ExitUnsafe), and the run must have ended (ExitNotRunning). rec, the
// record on this computer or nil, lets a run whose process is gone count
// as ended.
func RemoveScript(id string, rec *store.ExecSession) (string, error) {
	if err := CheckID(id); err != nil {
		return "", err
	}
	return FactsScript + `; r="$HOME/.komando"; s="$r/sessions"; d="$s/` + id + `"; ` + ownCheck +
		`ks_own "$r"; ks_own "$s"; ks_own "$d"; ` +
		ended + ` || ` + lostCheck(id, rec) + ` || exit ` + strconv.Itoa(ExitNotRunning) + `; rm -rf "$d"`, nil
}

// Sweep is the shell text that deletes every session folder whose run
// ended more than Retention ago by the server's own clock, and prints
// "swept ID" for each. It takes only folders right below
// ~/.komando/sessions whose name is a session ID, that are the login
// user's and not links; a running session is never swept. A run in recs
// (this host's records on this computer) whose process is gone is marked
// lost first, and so counts as ended. A sessions folder that is missing, a
// link or not the login user's: nothing is swept.
func Sweep(recs []*store.ExecSession) string {
	lost := ``
	for _, rec := range recs {
		if CheckID(rec.ID) == nil {
			lost += rec.ID + `) ` + lostCheck(rec.ID, rec) + ` && ` + markLost + `;; `
		}
	}
	return FactsScript + `; s="$HOME/.komando/sessions"; ` +
		`{ [ -d "$HOME/.komando" ] && [ ! -L "$HOME/.komando" ] && [ -O "$HOME/.komando" ] && [ -d "$s" ] && [ ! -L "$s" ] && [ -O "$s" ]; } || exit 0; ` +
		`now=$(date -u +%s); for d in "$s"/*; do n=${d##*/}; case "$n" in ` + idGlob() + `) ;; *) continue;; esac; ` +
		`[ ! -L "$d" ] && [ -d "$d" ] && [ -O "$d" ] || continue; ` +
		ended + ` || case "$n" in ` + lost + `*) ;; esac; ` + ended + ` || continue; ` +
		`b=$(head -c 16 "$d/started" 2>/dev/null | tr -d '\r\n'); case "$b" in ''|*[!0-9]*) continue;; esac; ` +
		`[ $((now - b)) -gt ` + strconv.Itoa(Retention) + ` ] || continue; rm -rf "$d" && echo "swept $n"; done; exit 0`
}

// BeginScript is a starting exec's one call: the sweep, then StartScript.
func BeginScript(s Start, recs []*store.ExecSession) (string, error) {
	start, err := StartScript(s)
	if err != nil {
		return "", err
	}
	return `( ` + Sweep(recs) + ` ); ` + start, nil
}

// Swept reads the IDs the sweep printed.
func Swept(stdout string) []string {
	var ids []string
	for _, line := range strings.Split(stdout, "\n") {
		if id, ok := strings.CutPrefix(line, "swept "); ok && CheckID(id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// idGlob is a shell pattern that matches a session ID and nothing else.
func idGlob() string { return strings.Repeat("[a-z2-7]", 52) }
