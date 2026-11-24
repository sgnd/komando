package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// stopServer is a session server whose stop and remove scripts exit with
// code; a stop that succeeds prints which it signalled, as the script does.
func stopServer(t *testing.T, code int) *sessionServer {
	t.Helper()
	srv := startSessionServer(t, "", true)
	answer := srv.answer
	srv.answer = func(cmd string) (string, int) {
		switch {
		case strings.Contains(cmd, "kill -") && code == 0 && strings.Contains(cmd, "echo 'signalled group'"):
			return "signalled group\n", 0
		case strings.Contains(cmd, "kill -") && code == 0:
			return "signalled pid\n", 0
		case strings.Contains(cmd, "kill -"), strings.Contains(cmd, `rm -rf "$d"`):
			return "", code
		}
		return answer(cmd)
	}
	return srv
}

func putExecSession(t *testing.T, rec *store.ExecSession) {
	t.Helper()
	if err := store.UpdateRuntime(store.Save(), func(s *store.State) error { s.ExecSessions[rec.ID] = rec; return nil }); err != nil {
		t.Fatal(err)
	}
}

func hasRecord(id string) bool {
	rt, _ := store.ReadRuntime()
	return rt != nil && rt.ExecSessions[id] != nil
}

type sessionChangeResult struct {
	Data struct {
		Session   string `json:"session"`
		Host      string `json:"host"`
		Signal    string `json:"signal"`
		Signalled string `json:"signalled"`
		PID       int    `json:"pid"`
		Removed   bool   `json:"removed"`
		WouldRun  string `json:"would_run"`
	} `json:"data"`
}

// runChange runs komando and reads its one JSON result from stdout.
func runChange(t *testing.T, args ...string) (sessionChangeResult, error) {
	t.Helper()
	var w bytes.Buffer
	savedW, savedErr := tcl.out.W, tcl.out.Err
	tcl.out.W, tcl.out.Err = &w, io.Discard
	err := runRoot(t, args...)
	tcl.out.W, tcl.out.Err = savedW, savedErr
	var res sessionChangeResult
	if err == nil {
		if e := json.Unmarshal(w.Bytes(), &res); e != nil {
			t.Fatalf("result: %v\n%s", e, w.String())
		}
	}
	return res, err
}

// U8 and U15: --stop signals the group of the process in the record on
// this computer, checks its start in the same call, records the change in
// the audit log, and keeps the record (the removal drops it).
func TestExecSessionStop(t *testing.T) {
	srv := stopServer(t, 0)
	putRecord(t, attachID, "alice", false)
	res, err := runChange(t, "exec", "dev", "--attach", attachID, "--stop", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if d := res.Data; d.Session != attachID || d.Host != "dev" || d.Signal != "TERM" || d.Signalled != "group" || d.PID != 4242 {
		t.Fatalf("result %+v", d)
	}
	e := srv.take()
	if len(e) != 1 || !strings.Contains(e[0].cmd, "kill -TERM -4242") || !strings.Contains(e[0].cmd, `!= 'proc 99'`) || strings.HasPrefix(e[0].cmd, "sudo") {
		t.Fatalf("execs %+v", e)
	}
	if !hasRecord(attachID) {
		t.Fatal("the stop dropped the record")
	}
	if a := lastAudit(t); a["command"] != "exec" || a["ok"] != true || a["stop"] != "TERM" || a["pid"] != float64(4242) {
		t.Fatalf("audit %v", a)
	}
}

// A-C324-3: a run that does not lead its own group is signalled by PID
// alone, and the result says so; --signal picks the signal.
func TestExecSessionStopPidAndSignal(t *testing.T) {
	srv := stopServer(t, 0)
	putExecSession(t, &store.ExecSession{ID: attachID, Host: "dev", PID: 4242, PGID: 4000, ProcStart: "proc 99"})
	res, err := runChange(t, "exec", "dev", "--attach", attachID, "--stop", "--signal", "KILL", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if res.Data.Signal != "KILL" || res.Data.Signalled != "pid" {
		t.Fatalf("result %+v", res.Data)
	}
	if e := srv.take(); len(e) != 1 || !strings.Contains(e[0].cmd, "kill -KILL 4242 ") || strings.Contains(e[0].cmd, "-4000") {
		t.Fatalf("execs %+v", e)
	}
}

// A-C324-2: a run under sudo is stopped through sudo as the same user.
func TestExecSessionStopSudo(t *testing.T) {
	srv := stopServer(t, 0)
	putExecSession(t, &store.ExecSession{ID: attachID, Host: "dev", PID: 4242, PGID: 4242, ProcStart: "proc 99", Sudo: true, SudoUser: "bob"})
	if _, err := runChange(t, "exec", "dev", "--attach", attachID, "--stop", "--yes"); err != nil {
		t.Fatal(err)
	}
	if e := srv.take(); len(e) != 1 || !strings.HasPrefix(e[0].cmd, "sudo -n -u 'bob' sh -c ") {
		t.Fatalf("execs %+v", e)
	}
}

// A-C324-2: with the server's sudo password reference, the password goes
// as input, never on the command line, and sudo is first asked whether it
// needs one.
func TestExecSessionStopSudoPassword(t *testing.T) {
	srv := stopServer(t, 0)
	const pw = "hunter2-Sudo-pw"
	if err := vault.Set(store.Save(), "dev-sudo", pw); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["dev"].SudoRef = "secret:dev-sudo"; return nil }); err != nil {
		t.Fatal(err)
	}
	putExecSession(t, &store.ExecSession{ID: attachID, Host: "dev", PID: 4242, PGID: 4242, ProcStart: "proc 99", Sudo: true})
	if _, err := runChange(t, "exec", "dev", "--attach", attachID, "--stop", "--yes"); err != nil {
		t.Fatal(err)
	}
	e := srv.take()
	if len(e) != 1 || strings.Contains(e[0].cmd, pw) || e[0].stdin != pw+"\n" || !strings.HasPrefix(e[0].cmd, "if sudo -n sh -c : 2>/dev/null; then sudo -n sh -c ") {
		t.Fatalf("execs %+v", e)
	}
	// a run without sudo is stopped without it, and the password stays here
	putExecSession(t, &store.ExecSession{ID: attachID, Host: "dev", PID: 4242, PGID: 4242, ProcStart: "proc 99"})
	if _, err := runChange(t, "exec", "dev", "--attach", attachID, "--stop", "--yes"); err != nil {
		t.Fatal(err)
	}
	if e := srv.take(); len(e) != 1 || e[0].stdin != "" || strings.Contains(e[0].cmd, "sudo") {
		t.Fatalf("execs %+v", e)
	}
}

// The stop script's exits: the stored process gone (or its PID reused)
// is SESSION_PROCESS_MISSING; any other failure SESSION_STOP_FAILED.
func TestExecSessionStopExits(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{{92, "SESSION_PROCESS_MISSING"}, {1, "SESSION_STOP_FAILED"}} {
		t.Run(tc.want, func(t *testing.T) {
			stopServer(t, tc.code)
			putRecord(t, attachID, "alice", false)
			_, err := runChange(t, "exec", "dev", "--attach", attachID, "--stop", "--yes")
			if errCode(err) != tc.want {
				t.Fatalf("got %v", err)
			}
			if a := lastAudit(t); a["ok"] != false || a["stop"] != "TERM" {
				t.Fatalf("audit %v", a)
			}
		})
	}
}

// Refusals before komando connects: what is not a stop or a remove of
// one session, a signal outside the list, and a run this computer did not
// start (A-C324-1: the record is the only source).
func TestExecSessionStopRefusals(t *testing.T) {
	srv := stopServer(t, 0)
	putExecSession(t, &store.ExecSession{ID: "b" + attachID[1:], Host: "prod", PID: 4242, PGID: 4242, ProcStart: "proc 99"})
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--attach", attachID, "--stop", "--signal", "USR1"}, "USAGE"},
		{[]string{"--attach", attachID, "--stop", "--signal", "term"}, "USAGE"},
		{[]string{"--attach", attachID, "--stop", "--remove"}, "USAGE"},
		{[]string{"--attach", attachID + ",c" + attachID[1:], "--stop"}, "USAGE"},
		{[]string{"--attach", attachID + ",c" + attachID[1:], "--remove"}, "USAGE"},
		{[]string{"--attach", attachID, "--stop", "--offset", "3"}, "USAGE"},
		{[]string{"--attach", attachID, "--remove", "--wait", "3s"}, "USAGE"},
		{[]string{"--attach", attachID, "--signal", "KILL"}, "USAGE"},
		{[]string{"--stop"}, "USAGE"},
		{[]string{"--remove"}, "USAGE"},
		{[]string{"--attach", attachID, "--stop", "--", "uptime"}, "USAGE"},
		{[]string{"--remove", "--", "uptime"}, "USAGE"},
		{[]string{"--signal", "KILL", "--", "uptime"}, "USAGE"},
		{[]string{"--attach", "../x", "--remove"}, "USAGE"},
		{[]string{"--attach", attachID, "--stop"}, "SESSION_RECORD_MISSING"},
		{[]string{"--attach", "b" + attachID[1:], "--stop"}, "SESSION_RECORD_MISSING"},
	} {
		if _, err := runChange(t, append([]string{"exec", "dev"}, tc.args...)...); errCode(err) != tc.want {
			t.Errorf("%v: got %v, want %s", tc.args, err, tc.want)
		}
	}
	if e := srv.take(); len(e) != 0 {
		t.Fatalf("connected: %+v", e)
	}
}

// U14: --stop and --remove are changes, as job kill is: a protected
// server refuses them without --yes, before komando connects, and the
// audit log records the refusal. (dev, the same address as prod, is
// protected too: the other tests pass --yes.)
func TestExecSessionChangeTier(t *testing.T) {
	for _, flag := range []string{"--stop", "--remove"} {
		t.Run(flag, func(t *testing.T) {
			srv := stopServer(t, 0)
			putExecSession(t, &store.ExecSession{ID: attachID, Host: "prod", PID: 4242, PGID: 4242, ProcStart: "proc 99"})
			if _, err := runChange(t, "exec", "prod", "--attach", attachID, flag); errCode(err) != "PROTECTED_TARGET" {
				t.Fatalf("want PROTECTED_TARGET, got %v", err)
			}
			if e := srv.take(); len(e) != 0 {
				t.Fatalf("connected: %+v", e)
			}
			if a := lastAudit(t); a["ok"] != false || a["blocked"] != "PROTECTED_TARGET" {
				t.Fatalf("audit %v", a)
			}
			if !hasRecord(attachID) {
				t.Fatal("the record is gone")
			}
		})
	}
}

// --dry-run shows the script and runs nothing.
func TestExecSessionChangeDryRun(t *testing.T) {
	srv := stopServer(t, 0)
	putRecord(t, attachID, "alice", false)
	res, err := runChange(t, "exec", "dev", "--attach", attachID, "--stop", "--dry-run", "--yes")
	if err != nil || !strings.Contains(res.Data.WouldRun, "kill -TERM -4242") {
		t.Fatalf("result %+v, err %v", res.Data, err)
	}
	if e := srv.take(); len(e) != 0 {
		t.Fatalf("ran: %+v", e)
	}
}

// U11: --remove deletes a finished session and drops its record. With a
// record, the stored process decides it has ended; without one, the
// files on the server.
func TestExecSessionRemove(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record bool
		host   string
	}{{"with a record", true, "dev"}, {"without a record", false, ""}, {"with another server's record", false, "prod"}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := stopServer(t, 0)
			if tc.host != "" {
				putExecSession(t, &store.ExecSession{ID: attachID, Host: tc.host, PID: 4242, PGID: 4242, ProcStart: "proc 99", Actor: "bob", Agent: true})
			}
			res, err := runChange(t, "exec", "dev", "--attach", attachID, "--remove", "--yes")
			if err != nil || !res.Data.Removed || res.Data.Session != attachID {
				t.Fatalf("result %+v, err %v", res.Data, err)
			}
			e := srv.take()
			if len(e) != 1 || !strings.Contains(e[0].cmd, `rm -rf "$d"`) || strings.Contains(e[0].cmd, "ks_start 4242") != tc.record {
				t.Fatalf("execs %+v", e)
			}
			if hasRecord(attachID) != (tc.host == "prod") {
				t.Fatal("the record of this server stayed, or another server's went")
			}
			if a := lastAudit(t); a["command"] != "exec" || a["ok"] != true || a["remove"] != true {
				t.Fatalf("audit %v", a)
			}
		})
	}
}

// --remove refuses a run that has not ended (stop it first), a folder that
// is not there or not safe; the record stays.
func TestExecSessionRemoveExits(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{{92, "SESSION_RUNNING"}, {95, "SESSION_FOLDER_MISSING"}, {90, "SESSION_FOLDER_DENIED"}} {
		t.Run(tc.want, func(t *testing.T) {
			stopServer(t, tc.code)
			putRecord(t, attachID, "alice", false)
			if _, err := runChange(t, "exec", "dev", "--attach", attachID, "--remove", "--yes"); errCode(err) != tc.want {
				t.Fatalf("got %v", err)
			}
			if !hasRecord(attachID) {
				t.Fatal("the record is gone")
			}
		})
	}
}
