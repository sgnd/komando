package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
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

// U14: --stop and --remove are changes: a protected
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
	}{{92, "SESSION_BUSY"}, {95, "SESSION_FOLDER_MISSING"}, {90, "SESSION_FOLDER_DENIED"}} {
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

// otherActorSetup unprotects the fake servers, so only the check for a run
// another actor started can ask, and stands in for the window: shown says
// whether one could be shown, allow what the person answers. It returns
// the texts the window showed.
func otherActorSetup(t *testing.T, shown, allow bool) *[]string {
	t.Helper()
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["prod"].Protected, st.Hosts["dev"].Protected = false, false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	texts := &[]string{}
	savedAsk := askOnScreen
	askOnScreen = func(_ *call, text string) (bool, bool) { *texts = append(*texts, text); return allow, shown }
	t.Cleanup(func() { askOnScreen = savedAsk; setGate(tcl, false, gateYes); resetApproval() })
	return texts
}

// An AI agent that stops or removes a run another actor started (a
// person, a script, or another agent) asks the person in the window; its
// own runs, a caller that is not an agent, and --remove without a record
// stay at the change tier.
func TestExecSessionAgentChangesAnotherActorsRun(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rec   *store.ExecSession // nil: no record
		agent bool               // the caller is an AI agent
		flag  string
		asks  bool
	}{
		{"an agent stops a person's run", &store.ExecSession{Actor: "alice"}, true, "--stop", true},
		{"an agent stops another actor's agent run", &store.ExecSession{Actor: "bob", Agent: true}, true, "--stop", true},
		{"an agent removes a person's run", &store.ExecSession{Actor: "alice"}, true, "--remove", true},
		{"an agent removes another actor's agent run", &store.ExecSession{Actor: "bob", Agent: true}, true, "--remove", true},
		{"an agent stops its own run", &store.ExecSession{Actor: "alice", Agent: true}, true, "--stop", false},
		{"an agent removes its own run", &store.ExecSession{Actor: "alice", Agent: true}, true, "--remove", false},
		{"a script stops an agent's run", &store.ExecSession{Actor: "bob", Agent: true}, false, "--stop", false},
		{"a script removes an agent's run", &store.ExecSession{Actor: "bob", Agent: true}, false, "--remove", false},
		{"an agent removes without a record", nil, true, "--remove", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := stopServer(t, 0)
			texts := otherActorSetup(t, true, true)
			setCallerEnv(t, "KOMANDO_ACTOR", "alice")
			if tc.agent { // TestMain clears every agent variable; a set one, even empty, marks an agent
				setCallerEnv(t, "KOMANDO_AGENT", "1")
			}
			if tc.rec != nil {
				rec := *tc.rec
				rec.ID, rec.Host, rec.PID, rec.PGID, rec.ProcStart = attachID, "dev", 4242, 4242, "proc 99"
				putExecSession(t, &rec)
			}
			args := []string{"exec", "dev", "--attach", attachID, tc.flag}
			if tc.agent { // a script needs no --yes here; with one it would pass any window check unseen
				args = append(args, "--yes")
			}
			if _, err := runChange(t, args...); err != nil {
				t.Fatal(err)
			}
			if asked := slices.ContainsFunc(*texts, func(s string) bool { return strings.Contains(s, "not by this AI agent") }); asked != tc.asks {
				t.Fatalf("asked %v, want %v: %q", asked, tc.asks, *texts)
			}
			if e := srv.take(); len(e) != 1 {
				t.Fatalf("execs %+v", e)
			}
		})
	}
}

// Without the person's yes (no --yes, no window, or Deny) the agent is
// stopped before it connects, the audit log records the refusal, and the
// record stays.
func TestExecSessionAgentStopsAnotherActorsRunRefused(t *testing.T) {
	for _, tc := range []struct {
		name         string
		yes          bool
		shown, allow bool
		code         string
	}{
		{"no --yes", false, true, true, "CONFIRM_REQUIRED"},
		{"no window", true, false, false, "CONFIRM_REQUIRED"},
		{"Deny", true, true, false, "CONFIRM_REQUIRED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := stopServer(t, 0)
			otherActorSetup(t, tc.shown, tc.allow)
			setCallerEnv(t, "KOMANDO_ACTOR", "bob")
			setCallerEnv(t, "KOMANDO_AGENT", "1")
			putRecord(t, attachID, "alice", false)
			args := []string{"exec", "dev", "--attach", attachID, "--stop"}
			if tc.yes {
				args = append(args, "--yes")
			}
			_, err := runChange(t, args...)
			if e := toErr(err); e == nil || e.Code != tc.code || e.Exit != 6 {
				t.Fatalf("want %s exit 6, got %v", tc.code, err)
			}
			if e := srv.take(); len(e) != 0 {
				t.Fatalf("connected: %+v", e)
			}
			if a := lastAudit(t); a["ok"] != false || a["blocked"] != tc.code {
				t.Fatalf("audit %v", a)
			}
			if !hasRecord(attachID) {
				t.Fatal("the record is gone")
			}
		})
	}
}

// On a protected server an agent that stops or removes another
// actor's run sees ONE window that names the starter and the protected
// server: the protected change's window must not answer for a starter it
// never showed.
func TestExecSessionAgentOtherStarterOnProtectedHost(t *testing.T) {
	for _, flag := range []string{"--stop", "--remove"} {
		t.Run(flag, func(t *testing.T) {
			srv := stopServer(t, 0)
			var texts []string
			savedAsk := askOnScreen
			askOnScreen = func(_ *call, text string) (bool, bool) { texts = append(texts, text); return true, true }
			t.Cleanup(func() { askOnScreen = savedAsk; setGate(tcl, false, gateYes); resetApproval() })
			setCallerEnv(t, "KOMANDO_ACTOR", "bob")
			setCallerEnv(t, "KOMANDO_AGENT", "1")
			putRecord(t, attachID, "alice", false)
			if _, err := runChange(t, "exec", "dev", "--attach", attachID, flag, "--yes"); err != nil {
				t.Fatal(err)
			}
			if len(texts) != 1 || !strings.Contains(texts[0], "started by alice at a terminal or in a script") || !strings.Contains(texts[0], protChangePrefix+"host dev") {
				t.Fatalf("want one window naming the starter and the protected server, got %q", texts)
			}
			if e := srv.take(); len(e) != 1 {
				t.Fatalf("execs %+v", e)
			}
		})
	}
}
