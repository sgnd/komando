package execsession

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Retention is how long a finished session stays when nobody removes it.
const Retention = 7 * 24 * 60 * 60

// ownCheck refuses (ExitUnsafe) a path that is a link or not a folder of
// the login user, and exits ExitGone when it is not there.
const ownCheck = `ks_own() { if [ -L "$1" ]; then exit 90; fi; [ -e "$1" ] || exit 95; { [ -d "$1" ] && [ -O "$1" ]; } || exit 90; }; `

// ended is true in shell when the files in $d say the run is over: it
// wrote exit, was stopped (killed), or was found lost. The running command
// can write each of them itself, so where a record exists its process
// decides (lostCheck); the files alone decide only without one.
const ended = `{ [ -f "$d/exit" ] || [ -f "$d/killed" ] || [ -f "$d/lost" ]; }`

// usable says whether rec is id's record and names a process: a PID above
// 1 and its start. Only a usable record speaks for the process.
func usable(id string, rec *store.ExecSession) bool {
	return rec != nil && rec.ID == id && rec.PID > 1 && rec.ProcStart != ""
}

// lostCheck is true in shell when rec's process, by the PID and start in
// the record on this computer, is no longer the live one: the run's root
// died without writing exit or killed (a reboot, an OOM kill). Never the
// pid file on the server: the running command owns it. A record that
// is not id's, or has no usable PID or start, never counts as lost.
func lostCheck(id string, rec *store.ExecSession) string {
	if !usable(id, rec) {
		return "false"
	}
	return `[ "$(ks_start ` + strconv.Itoa(rec.PID) + `)" != ` + sshx.Q(rec.ProcStart) + ` ]`
}

// markLost writes the lost mark; with noclobber it is never written
// through a link the run left there.
const markLost = `(set -C; : > "$d/lost") 2>/dev/null; `

// RemoveScript is the shell text that deletes one finished session: the
// folder and the two above it must be the login user's and not links
// (ExitUnsafe), and the run must have ended (ExitNotRunning). With rec,
// the record on this computer, the run has ended only when its stored
// process is gone, whatever files the run wrote; without it, the files
// decide.
func RemoveScript(id string, rec *store.ExecSession) (string, error) {
	if err := CheckID(id); err != nil {
		return "", err
	}
	over := ended
	if usable(id, rec) {
		over = lostCheck(id, rec)
	}
	return FactsScript + `; r="$HOME/.komando"; s="$r/sessions"; d="$s/` + id + `"; ` + ownCheck +
		`ks_own "$r"; ks_own "$s"; ks_own "$d"; ` +
		over + ` || exit ` + strconv.Itoa(ExitNotRunning) + `; rm -rf "$d"`, nil
}

// Sweep is the shell text that deletes every session folder whose run
// ended more than Retention ago by the server's own clock, and prints
// "swept ID" for each. It takes only folders right below
// ~/.komando/sessions whose name is a session ID, that are the login
// user's and not links; a running session is never swept. A folder with a
// record in recs (this host's records on this computer) is decided by its
// process alone: a live one is skipped whatever files the run wrote, and a
// gone one is marked lost when it wrote no end, so counts as ended. The
// files alone decide only for folders without a record. A sessions folder
// that is missing, a link or not the login user's: nothing is swept.
func Sweep(recs []*store.ExecSession) string {
	known := ``
	for _, rec := range recs {
		if CheckID(rec.ID) == nil && usable(rec.ID, rec) {
			known += rec.ID + `) ` + lostCheck(rec.ID, rec) + ` || continue; ` +
				`{ [ -f "$d/exit" ] || [ -f "$d/killed" ]; } || ` + markLost + `;; `
		}
	}
	return FactsScript + `; s="$HOME/.komando/sessions"; ` +
		`{ [ -d "$HOME/.komando" ] && [ ! -L "$HOME/.komando" ] && [ -O "$HOME/.komando" ] && [ -d "$s" ] && [ ! -L "$s" ] && [ -O "$s" ]; } || exit 0; ` +
		`now=$(date -u +%s); for d in "$s"/*; do n=${d##*/}; case "$n" in ` + idGlob() + `) ;; *) continue;; esac; ` +
		`[ ! -L "$d" ] && [ -d "$d" ] && [ -O "$d" ] || continue; ` +
		`case "$n" in ` + known + `*) ;; esac; ` + ended + ` || continue; ` +
		`b=$(head -c 16 "$d/started" 2>/dev/null | tr -d '\r\n'); case "$b" in ''|*[!0-9]*) continue;; esac; ` +
		`[ $((now - b)) -gt ` + strconv.Itoa(Retention) + ` ] || continue; rm -rf "$d" && echo "swept $n"; done; exit 0`
}

// BeginScript is a starting exec's one call: the sweep, between markers
// that carry the new session's ID, then StartScript.
func BeginScript(s Start, recs []*store.ExecSession) (string, error) {
	start, err := StartScript(s)
	if err != nil {
		return "", err
	}
	return `echo "sweep-begin ` + s.ID + `"; ( ` + Sweep(recs) + ` ); echo "sweep-end ` + s.ID + `"; ` + start, nil
}

// Swept reads the IDs the sweep of session id's start printed. Only the
// lines between its markers count, which carry the new session's ID (a
// login banner or a profile script may print first and cannot know it);
// only the first such block, and only when it ends. An ID twice in it:
// nothing is read.
func Swept(stdout, id string) []string {
	var ids []string
	inside := false
	for _, line := range strings.Split(stdout, "\n") {
		switch {
		case line == "sweep-begin "+id && !inside:
			inside = true
			continue
		case line == "sweep-end "+id && inside:
			return ids
		case !inside:
			continue
		}
		if n, ok := strings.CutPrefix(strings.TrimSuffix(line, "\r"), "swept "); ok && CheckID(n) == nil {
			if slices.Contains(ids, n) {
				return nil
			}
			ids = append(ids, n)
		}
	}
	return nil
}

// RemoveExit is the error for a remove's exit code: nil for 0.
// ExitNotRunning is SESSION_BUSY (stop it first); a folder that is not
// there or not safe is the same error as for a read.
func RemoveExit(host, id string, exit int) error {
	switch exit {
	case 0:
		return nil
	case ExitNotRunning:
		return out.Errf(out.ExitConflict, "SESSION_BUSY",
			"stop it first with `komando exec TARGET --attach ID --stop`, then remove it once it has ended",
			"session %s on %s is still running", id, host)
	case ExitGone, ExitUnsafe:
		return Follow{Host: host, ID: id}.readExit(exit)
	}
	return fmt.Errorf("%s: the session remove failed (exit %d)", host, exit)
}

// idGlob is a shell pattern that matches a session ID and nothing else.
func idGlob() string { return strings.Repeat("[a-z2-7]", 52) }
