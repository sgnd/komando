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

// ExitNotRunning is the stop script's exit when the stored process is not
// the live one: gone, or its PID reused by another process.
const ExitNotRunning = 92

// ExitStillRunning is the stop script's exit when the run's root is still
// alive after the wait: the signal was sent, and the run goes on.
const ExitStillRunning = 96

// Signals a stop may send. A run in a session runs in the background with
// no job control, so it ignores INT and QUIT, and nohup makes it ignore HUP.
var Signals = []string{"TERM", "KILL"}

// CheckSignal refuses a signal a stop does not send.
func CheckSignal(sig string) error {
	if !slices.Contains(Signals, sig) {
		return out.Usage("--signal %q: a run in a session takes TERM or KILL (it runs in the background, so it ignores INT and QUIT, and nohup makes it ignore HUP)", sig)
	}
	return nil
}

// ForStop finds the record a stop works from. The record on this computer
// is the only source: the session folder on the server belongs to the
// running command, which could rewrite the pid and start written there.
func ForStop(rt *store.Runtime, host, id string) (*store.ExecSession, error) {
	if err := CheckID(id); err != nil {
		return nil, err
	}
	rec := rt.ExecSessions[id]
	if rec == nil || rec.Host != host {
		return nil, out.Errf(out.ExitNotFound, "SESSION_RECORD_MISSING",
			"only the computer that started the run can stop it: run `komando host ssh exec TARGET --attach ID --stop` there; `komando audit list` there shows the exec that started it",
			"session %s on %s was not started from this computer", id, host)
	}
	return rec, nil
}

// StopScript is the shell text that sends sig to a run, built from its
// record alone: it checks that the live process started when the record
// says (exit ExitNotRunning when not), then signals the whole group when
// the run leads its own group (PGID equal to PID) and only the PID
// otherwise, and prints which ("signalled group" or "signalled pid").
func StopScript(rec *store.ExecSession, sig string) (string, error) {
	if err := CheckSignal(sig); err != nil {
		return "", err
	}
	if rec.PID <= 1 || rec.PGID <= 1 || rec.ProcStart == "" {
		return "", fmt.Errorf("session %s: the record has no usable pid, group or start", rec.ID)
	}
	p := strconv.Itoa(rec.PID)
	kill := `kill -` + sig + ` ` + p + ` && echo 'signalled pid'`
	if rec.PGID == rec.PID {
		kill = `kill -` + sig + ` -` + p + ` && echo 'signalled group'`
	}
	return FactsScript + `; now=$(ks_start ` + p + `); ` +
		`if [ -z "$now" ] || [ "$now" != ` + sshx.Q(rec.ProcStart) + ` ]; then exit ` + strconv.Itoa(ExitNotRunning) + `; fi; ` +
		kill, nil
}

// StopCommand is StopScript run as the run ran: a run under sudo is
// stopped through sudo as the same user, and the start check runs inside
// that same sudo call. With a password (the host's sudo reference, sent as
// the command's input) sudo is first asked whether it needs one. Around it,
// as the login user: the killed mark before (markStopped), the wait for the
// run's ending after (awaitEnding).
func StopCommand(rec *store.ExecSession, sig string, password bool) (string, error) {
	inner, err := StopScript(rec, sig)
	if err != nil {
		return "", err
	}
	if err := CheckID(rec.ID); err != nil {
		return "", err
	}
	stop := inner
	if rec.Sudo || rec.SudoUser != "" {
		user := ""
		if rec.SudoUser != "" {
			user = "-u " + sshx.Q(rec.SudoUser) + " "
		}
		sh := "sh -c " + sshx.Q(inner)
		stop = "sudo -n " + user + sh
		if password {
			stop = `if sudo -n ` + user + `sh -c : 2>/dev/null; then sudo -n ` + user + sh + `; else sudo -S -p '' ` + user + sh + `; fi`
		}
	}
	return markStopped(rec.ID, sig) + `( ` + stop + ` ); c=$?; ` +
		`if [ $c -ne 0 ]; then [ -z "$m" ] || rm -f "$d/killed"; exit $c; fi; ` + awaitEnding(rec, sig), nil
}

// markStopped writes killed ("TERM stop") in the session's folder as the
// login user, before the signal: the run's root then writes no exit, and a
// read says how it ended. Only in a folder of the login user that is no
// link, and with noclobber, never through a link the run left there; m is
// set when this stop wrote the mark, so a stop that signals nothing takes
// it back. No folder there: the stop still signals.
func markStopped(id, sig string) string {
	return `r="$HOME/.komando"; s="$r/sessions"; d="$s/` + id + `"; m=; ` + ownCheck +
		`if ( ks_own "$r"; ks_own "$s"; ks_own "$d" ) 2>/dev/null; then ` +
		`(set -C; printf '%s stop\n' ` + sshx.Q(sig) + ` > "$d/killed") 2>/dev/null && m=1; fi; `
}

// awaitEnding waits up to 5 s for the run's root to end (it ends after the
// capper wrote the log), so a read right after the stop has the whole
// output. A root still alive then goes on despite the signal: the stop
// takes its mark back and exits ExitStillRunning. KILL leaves the root no ending.
func awaitEnding(rec *store.ExecSession, sig string) string {
	if sig == "KILL" {
		return `exit 0`
	}
	alive := `[ -n "$m" ] && [ "$(ks_start ` + strconv.Itoa(rec.PID) + `)" = ` + sshx.Q(rec.ProcStart) + ` ]`
	return FactsScript + `; i=0; while ` + alive + ` && [ $i -lt 50 ]; do sleep 0.1 2>/dev/null || { sleep 1; i=$((i+9)); }; i=$((i+1)); done; ` +
		`if ` + alive + `; then rm -f "$d/killed"; echo 'signal sent; the run still runs'; exit ` + strconv.Itoa(ExitStillRunning) + `; fi; exit 0`
}

// StopExit is the error for a stop's exit code: nil for 0. ExitNotRunning
// is SESSION_PROCESS_MISSING: the stored process ended, or its PID belongs
// to another process now. ExitStillRunning is SESSION_STILL_RUNNING: the
// signal was sent and the run goes on. Any other is SESSION_STOP_FAILED
// with the server's words.
func StopExit(host, id string, exit int, stderr string) error {
	switch exit {
	case 0:
		return nil
	case ExitNotRunning:
		return out.Errf(out.ExitNotFound, "SESSION_PROCESS_MISSING",
			"`komando host ssh exec TARGET --attach ID` reads how it ended; `komando host ssh exec TARGET --attach ID --remove` removes it",
			"session %s on %s is not running: its process ended, or its PID belongs to another process now", id, host)
	case ExitStillRunning:
		return out.Errf(out.ExitConflict, "SESSION_STILL_RUNNING",
			"the run traps or ignores TERM; stop it hard with `komando host ssh exec TARGET --attach ID --stop --signal KILL`",
			"session %s on %s: the signal was sent, and the run still runs", id, host)
	}
	return out.Errf(out.ExitRemote, "SESSION_STOP_FAILED",
		"a run started with --sudo is stopped through sudo as the same user; when sudo asks for a password there, give the server its sudo password: `komando host ssh edit TARGET --sudo-credential NAME`",
		"%s: session %s was not stopped (exit %d): %s", host, id, exit, strings.TrimSpace(stderr))
}

// Signalled reads which a stop signalled: "group" or "pid", or "" when it
// printed neither.
func Signalled(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		switch strings.TrimSpace(line) {
		case "signalled group":
			return "group"
		case "signalled pid":
			return "pid"
		}
	}
	return ""
}
