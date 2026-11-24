//go:build !windows

package execsession

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

func runtimeWith(recs ...*store.ExecSession) *store.Runtime {
	rt := &store.Runtime{ExecSessions: map[string]*store.ExecSession{}}
	for _, r := range recs {
		rt.ExecSessions[r.ID] = r
	}
	return rt
}

// A stop takes its facts only from the record on this computer: a session
// that is not there, or is there for another server, cannot be stopped.
func TestForStop(t *testing.T) {
	rec := &store.ExecSession{ID: testID, Host: "web", PID: 41, PGID: 41, ProcStart: "proc 9"}
	rt := runtimeWith(rec)
	if got, err := ForStop(rt, "web", testID); err != nil || got != rec {
		t.Fatalf("%+v, %v", got, err)
	}
	for _, tt := range []struct{ host, id, code string }{
		{"db", testID, "SESSION_RECORD_MISSING"},
		{"web", strings.Repeat("b", 52), "SESSION_RECORD_MISSING"},
		{"web", "../" + testID[3:], "USAGE"},
	} {
		_, err := ForStop(rt, tt.host, tt.id)
		var oe *out.Error
		if !errors.As(err, &oe) || oe.Code != tt.code {
			t.Errorf("%s %s: %v, want %s", tt.host, tt.id, err, tt.code)
		}
	}
}

// runStop runs a stop script under sh and gives its output and exit code.
func runStop(t *testing.T, rec *store.ExecSession, sig string) (string, int) {
	t.Helper()
	text, err := StopScript(rec, sig)
	if err != nil {
		t.Fatal(err)
	}
	b, err := exec.Command("sh", "-c", text).CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(b), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), 0
}

// alive says pid still runs a moment after a signal could have reached
// it: there, and not a zombie.
func alive(pid int) bool {
	time.Sleep(300 * time.Millisecond)
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	b, _ := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return !strings.HasPrefix(strings.TrimSpace(string(b)), "Z")
}

// U8: with the PGID equal to the PID the whole group gets the signal: the
// child sleep is gone too.
func TestStopScriptGroup(t *testing.T) {
	leader, child := startGroup(t, true)
	f := facts(t, leader)
	got, code := runStop(t, &store.ExecSession{ID: testID, PID: f.PID, PGID: f.PGID, ProcStart: f.Start}, "TERM")
	if code != 0 || strings.TrimSpace(got) != "signalled group" {
		t.Fatalf("exit %d, %q", code, got)
	}
	if !gone(leader) || !gone(child) {
		t.Errorf("leader gone %v, child gone %v; want both", gone(leader), gone(child))
	}
}

// U8 (no setsid): a PGID that differs from the PID signals the PID only,
// and the output says so.
func TestStopScriptPIDOnly(t *testing.T) {
	leader, child := startGroup(t, false)
	f := facts(t, leader)
	if f.PGID == f.PID {
		t.Fatalf("the test process is its own group: %+v", f)
	}
	got, code := runStop(t, &store.ExecSession{ID: testID, PID: f.PID, PGID: f.PGID, ProcStart: f.Start}, "KILL")
	if code != 0 || strings.TrimSpace(got) != "signalled pid" {
		t.Fatalf("exit %d, %q", code, got)
	}
	if !gone(leader) {
		t.Error("the PID is still there")
	}
	if !alive(child) {
		t.Error("the child got the signal: only the PID should")
	}
}

// U10: a start that differs from the live process's (the PID was reused)
// refuses, and nothing is signalled.
func TestStopScriptPIDReused(t *testing.T) {
	leader, _ := startGroup(t, true)
	f := facts(t, leader)
	got, code := runStop(t, &store.ExecSession{ID: testID, PID: f.PID, PGID: f.PGID, ProcStart: f.Start + "0"}, "TERM")
	if code != ExitNotRunning {
		t.Fatalf("exit %d, %q; want %d", code, got, ExitNotRunning)
	}
	if !alive(leader) {
		t.Error("a process with another start got the signal")
	}
}

// U15: the stop script reads no file on the server: a pid file the run
// rewrote cannot aim it at another process.
func TestStopScriptReadsNoFile(t *testing.T) {
	text, err := StopScript(&store.ExecSession{ID: testID, PID: 4242, PGID: 4242, ProcStart: "proc 1"}, "TERM")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"$d", ".komando", "sessions", testID, "cat "} {
		if strings.Contains(text, s) {
			t.Errorf("the stop script holds %q: %s", s, text)
		}
	}
}

// U9 and the record's own sanity: only the five signals, never PID 0 or 1
// (kill -TERM -1 would reach every process the user may signal).
func TestStopScriptRefuses(t *testing.T) {
	ok := &store.ExecSession{ID: testID, PID: 4242, PGID: 4242, ProcStart: "proc 1"}
	for _, sig := range []string{"", "USR1", "term", "TERM;rm", "9", "SIGTERM"} {
		if _, err := StopScript(ok, sig); err == nil {
			t.Errorf("signal %q was taken", sig)
		}
	}
	for _, sig := range []string{"TERM", "INT", "HUP", "QUIT", "KILL"} {
		if _, err := StopScript(ok, sig); err != nil {
			t.Errorf("signal %s: %v", sig, err)
		}
	}
	for _, rec := range []*store.ExecSession{
		{ID: testID, PID: 1, PGID: 1, ProcStart: "proc 1"},
		{ID: testID, PID: 0, PGID: 0, ProcStart: "proc 1"},
		{ID: testID, PID: 4242, PGID: 1, ProcStart: "proc 1"},
		{ID: testID, PID: 4242, PGID: 4242, ProcStart: ""},
	} {
		if _, err := StopScript(rec, "TERM"); err == nil {
			t.Errorf("%+v was taken", rec)
		}
	}
}

// A run under sudo is stopped through sudo as the same user, with the
// start check inside the same sudo call (the whole script is its command).
func TestStopCommandSudo(t *testing.T) {
	base := store.ExecSession{ID: testID, PID: 4242, PGID: 4242, ProcStart: "proc 1"}
	inner, err := StopScript(&base, "TERM")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := StopCommand(&base, "TERM", false)
	if err != nil || plain != inner {
		t.Fatalf("no sudo: %q, %v", plain, err)
	}
	asApp := base
	asApp.Sudo, asApp.SudoUser = true, "app"
	got, err := StopCommand(&asApp, "TERM", false)
	if err != nil || !strings.HasPrefix(got, "sudo -n -u 'app' sh -c ") || !strings.Contains(got, "ks_start") {
		t.Fatalf("sudo -u app: %q, %v", got, err)
	}
	root := base
	root.Sudo = true
	got, err = StopCommand(&root, "TERM", true)
	if err != nil || !strings.Contains(got, "sudo -S -p '' sh -c ") || !strings.Contains(got, "sudo -n sh -c :") {
		t.Fatalf("root with a password: %q, %v", got, err)
	}
	if strings.Contains(got, "-u ") {
		t.Errorf("root run names a user: %q", got)
	}
}

// The hint of a stop from another computer names the stop to run there.
func TestForStopHintNamesTheStop(t *testing.T) {
	_, err := ForStop(runtimeWith(), "web", testID)
	var oe *out.Error
	if !errors.As(err, &oe) || !strings.Contains(oe.Hint, "`komando exec TARGET --attach ID --stop` there") {
		t.Fatalf("%v", err)
	}
}

func TestStopExit(t *testing.T) {
	if err := StopExit("web", testID, 0, ""); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		exit      int
		code      string
		outExit   int
		inMessage string
	}{
		{ExitNotRunning, "SESSION_PROCESS_MISSING", out.ExitNotFound, "is not running"},
		{1, "SESSION_STOP_FAILED", out.ExitRemote, "sudo: a password is required"},
	} {
		err := StopExit("web", testID, tt.exit, "sudo: a password is required\n")
		var oe *out.Error
		if !errors.As(err, &oe) || oe.Code != tt.code || oe.Exit != tt.outExit || !strings.Contains(oe.Message, tt.inMessage) {
			t.Errorf("exit %d: %v", tt.exit, err)
		}
	}
}

func TestSignalled(t *testing.T) {
	for in, want := range map[string]string{
		"signalled group\n":             "group",
		"banner\nsignalled pid\n":       "pid",
		"":                              "",
		"signalled groups\nsignalled\n": "",
	} {
		if got := Signalled(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestRemoveExit(t *testing.T) {
	if err := RemoveExit("web", testID, 0); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		exit    int
		code    string
		outExit int
	}{
		{ExitNotRunning, "SESSION_RUNNING", out.ExitConflict},
		{ExitGone, "SESSION_FOLDER_MISSING", out.ExitNotFound},
		{ExitUnsafe, "SESSION_FOLDER_DENIED", out.ExitRemote},
	} {
		err := RemoveExit("web", testID, tt.exit)
		var oe *out.Error
		if !errors.As(err, &oe) || oe.Code != tt.code || oe.Exit != tt.outExit {
			t.Errorf("exit %d: %v", tt.exit, err)
		}
	}
	if err := RemoveExit("web", testID, 1); err == nil || !strings.Contains(err.Error(), "remove failed (exit 1)") {
		t.Errorf("exit 1: %v", err)
	}
}
