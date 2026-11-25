package execsession

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// ExitNotRunning is the stop script's exit when the stored process is not
// the live one: gone, or its PID reused by another process.
const ExitNotRunning = 92

// Signals a stop may send.
var Signals = []string{"TERM", "INT", "HUP", "QUIT", "KILL"}

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
			"only the computer that started the run can stop it: stop it there; `komando audit` there shows the exec that started it",
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
	if !slices.Contains(Signals, sig) {
		return "", out.Usage("--signal %q: give one of TERM, INT, HUP, QUIT or KILL", sig)
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
// the command's input) sudo is first asked whether it needs one.
func StopCommand(rec *store.ExecSession, sig string, password bool) (string, error) {
	inner, err := StopScript(rec, sig)
	if err != nil {
		return "", err
	}
	if !rec.Sudo && rec.SudoUser == "" {
		return inner, nil
	}
	user := ""
	if rec.SudoUser != "" {
		user = "-u " + sshx.Q(rec.SudoUser) + " "
	}
	sh := "sh -c " + sshx.Q(inner)
	if !password {
		return "sudo -n " + user + sh, nil
	}
	return `if sudo -n ` + user + `sh -c : 2>/dev/null; then sudo -n ` + user + sh + `; else sudo -S -p '' ` + user + sh + `; fi`, nil
}
