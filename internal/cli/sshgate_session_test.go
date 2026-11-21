package cli

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// gateSessionLab is a key's komando (KOMANDO_SSH_GATE=ops) with the shell
// inventory, its terminal and SSH session played by the returned fakes.
func gateSessionLab(t *testing.T) (*fakeShell, *fakeTerm) {
	t.Helper()
	invHome(t)
	shellInventory(t)
	setCallerEnv(t, gateEnv, "ops")
	t.Setenv("SSH_CONNECTION", "203.0.113.7 51000 10.0.0.2 22")
	conn, tt := newFakeShell(), newFakeTerm(80, 24)
	savedDial, savedTTY := shellDial, shellTTY
	t.Cleanup(func() { shellDial, shellTTY = savedDial, savedTTY })
	shellDial = func(_ *call, _ context.Context, _ *store.State, _ *store.Host, fn func(shellConn) error) error {
		return fn(conn)
	}
	shellTTY = func() shellTerm { return tt }
	return conn, tt
}

// gateOpenShell runs openShell on server for the key, as runShell does
// once its checks pass.
func gateOpenShell(t *testing.T, server string) error {
	t.Helper()
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return openShell(tcl, context.Background(), st, st.Hosts[server])
}

// sessionRecords are the audit records of key shell sessions, oldest first.
func sessionRecords(t *testing.T) []map[string]any {
	t.Helper()
	var recs []map[string]any
	for _, line := range strings.Split(auditText(t), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) == nil && r["session"] != nil {
			recs = append(recs, r)
		}
	}
	return recs
}

// wantRecord checks the fields of an audit record.
func wantRecord(t *testing.T, r map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if got, _ := json.Marshal(r[k]); string(got) != mustJSON(t, v) {
			t.Errorf("record %s = %s, want %s (%v)", k, got, mustJSON(t, v), r)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A key's shell session is in the audit log when it starts and when it
// ends: the key's name, the server, how long it ran and why it ended.
func TestGateShellSessionRecords(t *testing.T) {
	conn, _ := gateSessionLab(t)
	conn.end <- nil // the person types exit
	if err := gateOpenShell(t, "web"); err != nil {
		t.Fatalf("openShell: %v", err)
	}
	recs := sessionRecords(t)
	if len(recs) != 2 {
		t.Fatalf("%d session records, want a start and an end: %v", len(recs), recs)
	}
	who := map[string]any{"command": "shell", "ssh_gate": "ops", "agent": "ssh-gate key ops", "hosts": []string{"web"},
		"shell_access": true, "client": "203.0.113.7"}
	wantRecord(t, recs[0], who)
	wantRecord(t, recs[0], map[string]any{"session": "start", "ok": true})
	if _, ok := recs[0]["duration_ms"]; ok {
		t.Errorf("the start record has a duration: %v", recs[0])
	}
	wantRecord(t, recs[1], who)
	wantRecord(t, recs[1], map[string]any{"session": "end", "end": "exit", "exit_code": 0, "ok": true})
	if d, ok := recs[1]["duration_ms"].(float64); !ok || d < 0 {
		t.Errorf("the end record's duration_ms is %v", recs[1]["duration_ms"])
	}
}

// A session whose connection breaks, or that never starts, still gets its
// end record, with why.
func TestGateShellSessionEndReasons(t *testing.T) {
	t.Run("lost", func(t *testing.T) {
		conn, _ := gateSessionLab(t)
		conn.end <- errors.New("connection reset")
		_ = gateOpenShell(t, "web")
		recs := sessionRecords(t)
		if len(recs) != 2 {
			t.Fatalf("records %v", recs)
		}
		wantRecord(t, recs[1], map[string]any{"session": "end", "end": "lost", "ok": false})
	})
	t.Run("error", func(t *testing.T) {
		gateSessionLab(t)
		shellDial = func(*call, context.Context, *store.State, *store.Host, func(shellConn) error) error {
			return errors.New("no route to host")
		}
		if err := gateOpenShell(t, "web"); err == nil {
			t.Fatal("a failed dial is no error")
		}
		recs := sessionRecords(t)
		if len(recs) != 2 {
			t.Fatalf("records %v", recs)
		}
		wantRecord(t, recs[1], map[string]any{"session": "end", "end": "error", "ok": false})
	})
}

// A shell that is not a key's keeps the plain shell record: no session records.
func TestShellNotKeyNoSessionRecords(t *testing.T) {
	conn, _ := gateSessionLab(t)
	setCallerEnv(t, gateEnv, "")
	conn.end <- nil
	if err := gateOpenShell(t, "web"); err != nil {
		t.Fatal(err)
	}
	if recs := sessionRecords(t); len(recs) != 0 {
		t.Errorf("session records for a person: %v", recs)
	}
}
