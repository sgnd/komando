package cli

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// audit adds one record per action to the sealed store's audit log: the
// command's own record, which a leaf running a body (runBody) names with
// its ID.
func audit(cl *call, st *store.State, command string, hosts []string, remote string, ok bool, extra map[string]any) {
	if cl.out.As != "" {
		command = cl.out.As
	}
	auditRecord(cl, st, command, "", hosts, remote, ok, extra)
}

// auditEvent adds a record of an event from auditEvents (host.key-pinned,
// secret.set) under the leaf that runs.
func auditEvent(cl *call, st *store.State, event string, hosts []string, remote string, ok bool, extra map[string]any) {
	if !slices.Contains(auditEvents, event) { // a bug: the list is closed (rule R1, C625)
		auditEventBug(event)
		cl.out.Warn(fmt.Sprintf("%q is not an audit event, so the audit log recorded it as event_invalid", event))
		withName := maps.Clone(extra)
		if withName == nil {
			withName = map[string]any{}
		}
		withName["event_invalid"] = event // the audit never fails open (audit A5)
		auditRecord(cl, st, runningLeaf(cl), "", hosts, remote, ok, withName)
		return
	}
	auditRecord(cl, st, runningLeaf(cl), event, hosts, remote, ok, extra)
}

// auditEventBug is told of an event outside the closed list: TestMain makes
// it panic, so the bug is found under test, not in the field.
var auditEventBug = func(string) {}

// auditRecord is the one writer of the audit log (rule R1, audit_identity.go).
func auditRecord(cl *call, st *store.State, command, event string, hosts []string, remote string, ok bool, extra map[string]any) {
	if st != nil && !st.Settings.Audit {
		return
	}
	// where else the record goes: a local of this record, never a field of
	// the call, as two dials of one command may pin keys at once
	var syslog string
	if st == nil { // always recorded (turning the audit off, too); read where else it goes
		if s, err := store.Load(); err == nil {
			syslog = s.Settings.AuditSyslog
		}
	} else {
		syslog = st.Settings.AuditSyslog
	}
	rec := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"command": command,
		"ok":      ok,
		"dry_run": cl.dryRun(),
		"actor":   actor(cl),
	}
	if hosts != nil {
		rec["hosts"] = hosts
	}
	if remote != "" {
		// the command as it ran, without the passwords, keys and tokens it
		// carried: the record is kept for years, and a copy of it goes to
		// the syslog server in clear text (audit_syslog)
		rec["remote"] = out.MaskSecrets(cl.out.RedactExact(remote))
	}
	if a := cl.caller().Agent; a != "" {
		rec["agent"] = a // who typed it: an AI agent
		if cl.sess.Allowed() {
			rec["allowed_by_person"] = true // in komando's window
		}
		// the agent's environment can give KOMANDO_ACTOR any name, so it
		// is the name it claims; the computer account comes from the system
		if cl.getenv("KOMANDO_ACTOR") != "" {
			rec["actor_claimed"] = true
		}
		rec["os_user"] = osUser()
	}
	if c := cl; len(c.ttyYes) > 0 || cl.promptConfirmed != "" {
		rec["confirm"] = "tty" // a person said yes at the terminal
		rec["confirmed"] = append(slices.Clone(c.ttyYes), slices.DeleteFunc([]string{cl.promptConfirmed}, func(s string) bool { return s == "" })...)
	}
	if cl.body != nil {
		rec["body_sha256"] = cl.body.sha256() // the window shows its first 16
	}
	if cl.askedInStep { // a person was asked while the store was locked (guard_before_lock.go)
		rec["asked_in_store_step"] = true
		rec["asked_in_store_step_command"] = command
	}
	for k, v := range extra {
		rec[k] = v
	}
	// after extra: no field of a call can change who the record names
	rec["command"] = command
	delete(rec, "safety_key")
	if k, found := auditKeyOf(command); found {
		rec["safety_key"] = keyRecord(k)
	}
	delete(rec, "event")
	if event != "" {
		rec["event"] = event
	}
	if rec["blocked"] != nil {
		cl.blockAudited = true
	}
	if err := appendAudit(cl, syslog, rec); err != nil {
		// the action ran (or was refused); its record is missing: say so
		cl.out.Warn(fmt.Sprintf("the audit log could not record %s: %v", command, err))
	}
}
