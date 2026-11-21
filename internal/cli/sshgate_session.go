package cli

import (
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// A key's shell session is in the audit log twice: when it starts and when
// it ends. The gate's own record says the key asked for it; these say the
// key's name, the server and, at the end, how long it ran and why it ended.
// What is typed inside is not recorded. Like the gate's records they are
// written even when the audit setting is off, and when the start record
// cannot be written, no shell opens.

// Why a key's shell session ended (the end record's "end").
const (
	sessionExit  = "exit"  // the shell ended (exit_code says how)
	sessionLost  = "lost"  // the connection to the server broke
	sessionError = "error" // the shell never started (connect, login, pty)
)

// gateSessionStart writes the record of a key's shell session on server as
// it starts.
func gateSessionStart(cl *call, st *store.State, server string) error {
	return gateSessionWrite(cl, st, gateSessionRecord(cl, server, "start"))
}

// gateSessionEnd writes the record of a key's shell session on server as it
// ends: after took, for the reason end, with the shell's exit code.
func gateSessionEnd(cl *call, st *store.State, server string, took time.Duration, end string, code int) error {
	rec := gateSessionRecord(cl, server, "end")
	rec["ok"] = end == sessionExit
	rec["end"] = end
	rec["duration_ms"] = took.Milliseconds()
	if end == sessionExit {
		rec["exit_code"] = code
	}
	return gateSessionWrite(cl, st, rec)
}

func gateSessionRecord(cl *call, server, session string) map[string]any {
	rec := map[string]any{
		"ts":           time.Now().UTC().Format(time.RFC3339Nano),
		"command":      "shell",
		"ok":           true,
		"dry_run":      false,
		"actor":        actor(cl),
		"os_user":      osUser(),
		"agent":        cl.caller().Agent,
		"ssh_gate":     strings.TrimPrefix(cl.caller().Agent, "ssh-gate key "),
		"hosts":        []string{server},
		"shell_access": true,
		"session":      session,
	}
	if from, _, _ := strings.Cut(cl.getenv("SSH_CONNECTION"), " "); from != "" {
		rec["client"] = from
	}
	return rec
}

func gateSessionWrite(cl *call, st *store.State, rec map[string]any) error {
	if err := appendAudit(cl, st.Settings.AuditSyslog, rec); err != nil {
		return out.Errf(out.ExitError, "AUDIT_UNAVAILABLE", "fix the file or folder permissions on the komando computer (`komando doctor` checks them)",
			"the audit log cannot be written (%v), so the key's shell session is not recorded", err)
	}
	return nil
}
