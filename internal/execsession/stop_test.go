//go:build !windows

package execsession

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

// U9 and the record's own sanity: only TERM and KILL, never PID 0 or 1
// (kill -TERM -1 would reach every process the user may signal).
func TestStopScriptRefuses(t *testing.T) {
	ok := &store.ExecSession{ID: testID, PID: 4242, PGID: 4242, ProcStart: "proc 1"}
	for _, sig := range []string{"", "USR1", "term", "TERM;rm", "9", "SIGTERM", "INT", "HUP", "QUIT"} {
		_, err := StopScript(ok, sig)
		var oe *out.Error
		if !errors.As(err, &oe) || oe.Code != "USAGE" || !strings.Contains(oe.Message, "TERM or KILL") {
			t.Errorf("signal %q: %v, want a usage error that names TERM or KILL", sig, err)
		}
	}
	for _, sig := range []string{"TERM", "KILL"} {
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
	if err != nil || !strings.Contains(plain, "( "+inner+" ); c=$?") || strings.Contains(plain, "sudo") {
		t.Fatalf("no sudo: %q, %v", plain, err)
	}
	asApp := base
	asApp.Sudo, asApp.SudoUser = true, "app"
	got, err := StopCommand(&asApp, "TERM", false)
	// the mark is the login user's: it is written before sudo, never inside it
	if err != nil || !strings.Contains(got, "( sudo -n -u 'app' sh -c ") || !strings.Contains(got, "ks_start") ||
		strings.Index(got, `> "$d/killed"`) > strings.Index(got, "sudo") {
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
	if !errors.As(err, &oe) || !strings.Contains(oe.Hint, "`komando host ssh exec TARGET --attach ID --stop` there") {
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
		{ExitStillRunning, "SESSION_STILL_BUSY", out.ExitConflict, "the run still runs"},
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
		{ExitNotRunning, "SESSION_BUSY", out.ExitConflict},
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

// runStopIn runs StopCommand (no sudo) as the login user with HOME home.
func runStopIn(t *testing.T, home string, rec *store.ExecSession, sig string) (string, int) {
	t.Helper()
	text, err := StopCommand(rec, sig, false)
	if err != nil {
		t.Fatal(err)
	}
	return runShOut(t, home, text)
}

// startStoppable starts the real run inner in a session of its own group,
// and gives its record once the run had a second to print.
func startStoppable(t *testing.T, home, inner string) *store.ExecSession {
	t.Helper()
	got, code := runStart(t, home, Start{ID: testID, Shown: "x", Run: startRun(inner), LogMax: 1 << 20}, "", fakeSetsid(t, "0", true))
	f, _, err := ReadStart("dev", code, got, testID)
	if err != nil {
		t.Fatalf("start: %v (exit %d) %q", err, code, got)
	}
	rec := &store.ExecSession{ID: testID, PID: f.PID, PGID: f.PGID, ProcStart: f.Start}
	t.Cleanup(func() { _ = syscall.Kill(-f.PGID, syscall.SIGKILL) })
	time.Sleep(time.Second)
	return rec
}

// readSession reads session testID in home with the real read script.
func readSession(t *testing.T, home string) (Status, string) {
	t.Helper()
	text, err := ReadScript(testID, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, code := runShOut(t, home, text)
	if code != 0 {
		t.Fatalf("read exit %d: %q", code, got)
	}
	st, data, err := ParseRead(got, testID)
	if err != nil {
		t.Fatal(err)
	}
	return st, string(data)
}

// C652: a stop marks the run killed with its signal before it signals, the
// output up to the stop stays in the log, and the run's own ending still
// runs: its exit written (T3), no lost mark, the fifo gone.
func TestStopCommandKeepsOutputAndMarksTheSignal(t *testing.T) {
	home := t.TempDir()
	rec := startStoppable(t, home, `echo a; sleep 30; echo late`)
	got, code := runStopIn(t, home, rec, "TERM")
	if code != 0 || !strings.Contains(got, "signalled group") {
		t.Fatalf("stop exit %d, %q", code, got)
	}
	st, data := readSession(t, home)
	if st.Killed != "TERM stop" || st.Lost || !st.Ended() {
		t.Errorf("status %+v, want killed TERM stop", st)
	}
	if data != "a\n" {
		t.Errorf("the log holds %q, want the output up to the stop", data)
	}
	for _, f := range []string{"lost", ".o"} {
		if _, err := os.Lstat(filepath.Join(sessionDir(home), f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s after a stop: %v", f, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(sessionDir(home), "exit")); err != nil {
		t.Errorf("no exit after the run's ending: %v", err)
	}
}

// T1: a run in the background ignores INT and QUIT, and nohup makes it
// ignore HUP: a stop with one of them is refused before anything runs, so
// no killed mark says the run ended while it goes on, and its exit is
// written when it really ends.
func TestStopCommandRefusesSignalsTheRunIgnores(t *testing.T) {
	home := t.TempDir()
	rec := startStoppable(t, home, `sleep 2`)
	for _, sig := range []string{"INT", "HUP", "QUIT"} {
		_, err := StopCommand(rec, sig, false)
		var oe *out.Error
		if !errors.As(err, &oe) || oe.Code != "USAGE" || !strings.Contains(oe.Message, "TERM or KILL") {
			t.Errorf("stop with %s: %v, want a usage error that names TERM or KILL", sig, err)
		}
	}
	if got := strings.TrimSpace(waitFile(t, home, "exit")); got != "0" {
		t.Errorf("exit %q, want 0", got)
	}
	if st, _ := readSession(t, home); st.Killed != "" || st.Exit != 0 || !st.Ended() {
		t.Errorf("status %+v, want ended with exit 0 and no killed mark", st)
	}
}

// T1: a root still alive after the wait got the signal and goes on (it
// traps or ignores it): the stop takes its mark back and says so with
// ExitStillRunning, so no read says the run ended.
func TestStopCommandSaysTheRunStillRuns(t *testing.T) {
	home := t.TempDir()
	d := sessionDir(home)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(d, ".o"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := exec.Command("sh", "-c", `trap '' TERM; while :; do sleep 1; done`)
	root.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := root.Start(); err != nil {
		t.Fatal(err)
	}
	pid := root.Process.Pid
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL); _ = root.Wait() })
	start, code := runShOut(t, home, FactsScript+"; ks_start "+strconv.Itoa(pid))
	if code != 0 || strings.TrimSpace(start) == "" {
		t.Fatalf("ks_start exit %d, %q", code, start)
	}
	rec := &store.ExecSession{ID: testID, PID: pid, PGID: pid, ProcStart: strings.TrimSpace(start)}
	got, code := runStopIn(t, home, rec, "TERM")
	if code != ExitStillRunning || !strings.Contains(got, "signal sent; the run still runs") {
		t.Errorf("stop exit %d, %q; want %d and the line that it still runs", code, got, ExitStillRunning)
	}
	if _, err := os.Lstat(filepath.Join(d, "killed")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the killed mark stayed while the run goes on: %v", err)
	}
	if syscall.Kill(pid, 0) != nil {
		t.Error("the root is gone; the test needs it alive")
	}
}

// T2: a run that ignores TERM goes on after a TERM stop, and so does its
// root: the root's wait returns when its own trap runs, and it waits for
// the run again, so the session does not read as ended, and a KILL stop
// still finds the recorded root.
func TestStopKeepsTheRootWhileTheRunIgnoresTERM(t *testing.T) {
	home := t.TempDir()
	rec := startStoppable(t, home, `trap '' TERM; sleep 30`)
	if got, code := runStopIn(t, home, rec, "TERM"); code != ExitStillRunning {
		t.Fatalf("TERM stop exit %d, %q; want %d", code, got, ExitStillRunning)
	}
	if syscall.Kill(rec.PID, 0) != nil {
		t.Fatal("the root ended while the run goes on")
	}
	if st, _ := readSession(t, home); st.Ended() {
		t.Errorf("status %+v while the run goes on, want not ended", st)
	}
	if got, code := runStopIn(t, home, rec, "KILL"); code != 0 {
		t.Fatalf("KILL stop exit %d, %q; want 0", code, got)
	}
	if !gone(rec.PID) {
		t.Error("the root is still there after KILL")
	}
}

// T3: the run ends on its own after the stop wrote its mark and before
// its start check (a slow ps or sed here): the stop finds no process and
// takes its mark back, and the run's exit code is still there, so the
// session reads as ended with it, not as lost.
func TestStopRaceKeepsTheExitCode(t *testing.T) {
	home := t.TempDir()
	rec := startStoppable(t, home, `sleep 2`)
	slow := t.TempDir()
	for _, tool := range []string{"ps", "sed"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		stub := "#!/bin/sh\nsleep 3\nexec " + real + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(slow, tool), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	text, err := StopCommand(rec, "TERM", false)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", text)
	cmd.Env = []string{"HOME=" + home, "PATH=" + slow + ":/usr/bin:/bin"}
	if got, err := cmd.Output(); exitOf(err) != ExitNotRunning {
		t.Fatalf("stop exit %d, %q; want %d", exitOf(err), got, ExitNotRunning)
	}
	st, _ := readSession(t, home)
	if !st.Ended() || st.Lost || st.Killed != "" || st.Exit != 0 {
		t.Errorf("status %+v, want ended with exit 0, no killed mark, not lost", st)
	}
	if _, err := os.Lstat(filepath.Join(sessionDir(home), "exit")); err != nil {
		t.Errorf("no exit file: %v", err)
	}
}

// noSetsidPath is a PATH folder with every program of /bin and /usr/bin but
// setsid, as on a BSD server.
func noSetsidPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, from := range []string{"/bin", "/usr/bin"} {
		ents, _ := os.ReadDir(from)
		for _, e := range ents {
			if e.Name() != "setsid" {
				_ = os.Symlink(filepath.Join(from, e.Name()), filepath.Join(dir, e.Name())) // a name in both: the first stays
			}
		}
	}
	return dir
}

// C652: without setsid the run has no group of its own and a stop signals
// the root alone; the root, which traps the signal for its ending, hands it
// to the run, so the run ends and the session says it was stopped.
func TestStopCommandWithoutSetsidEndsTheRun(t *testing.T) {
	home := t.TempDir()
	text, err := StartScript(Start{ID: testID, Shown: "x", Run: startRun(`echo $$ > "$HOME/run.pid"; echo a; sleep 30; echo late`), LogMax: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "umask 022; "+text)
	cmd.Env = []string{"HOME=" + home, "PATH=" + noSetsidPath(t)}
	got, err := cmd.Output()
	f, _, ferr := ReadStart("dev", exitOf(err), string(got), testID)
	if ferr != nil {
		t.Fatalf("start: %v (%v) %q", ferr, err, got)
	}
	time.Sleep(time.Second)
	b, err := os.ReadFile(filepath.Join(home, "run.pid"))
	if err != nil {
		t.Fatal(err)
	}
	run, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	t.Cleanup(func() { _ = syscall.Kill(run, syscall.SIGKILL); _ = syscall.Kill(f.PID, syscall.SIGKILL) })
	rec := &store.ExecSession{ID: testID, PID: f.PID, PGID: f.PGID, ProcStart: f.Start}
	if out, code := runStopIn(t, home, rec, "TERM"); code != 0 || !strings.Contains(out, "signalled pid") {
		t.Fatalf("stop exit %d, %q", code, out)
	}
	if !gone(run) {
		t.Error("the run goes on after the stop")
	}
	// the run's own children are out of reach here and may keep the output
	// open, so the log is not checked
	if st, _ := readSession(t, home); st.Killed != "TERM stop" {
		t.Errorf("status %+v, want killed TERM stop", st)
	}
}

// exitOf is the exit code of a command's error: 0 for none.
func exitOf(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 0
}

// C652: a stop that signals nothing (the stored process is not the live
// one) leaves no killed mark: the run's own end still decides.
func TestStopCommandUnmarksWhenNothingWasSignalled(t *testing.T) {
	home := t.TempDir()
	rec := startStoppable(t, home, `sleep 30`)
	stale := *rec
	stale.ProcStart += "0"
	if got, code := runStopIn(t, home, &stale, "TERM"); code != ExitNotRunning {
		t.Fatalf("stop exit %d, %q; want %d", code, got, ExitNotRunning)
	}
	if _, err := os.Lstat(filepath.Join(sessionDir(home), "killed")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a stop that signalled nothing left a killed mark: %v", err)
	}
}

// C652: the killed mark is never written through a link the run left in
// its folder; the stop still stops the run.
func TestStopCommandMarkNotThroughALink(t *testing.T) {
	home := t.TempDir()
	rec := startStoppable(t, home, `sleep 30`)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(sessionDir(home), "killed")); err != nil {
		t.Fatal(err)
	}
	if got, code := runStopIn(t, home, rec, "TERM"); code != 0 {
		t.Fatalf("stop exit %d, %q", code, got)
	}
	if b, _ := os.ReadFile(target); len(b) != 0 {
		t.Errorf("the mark went through the link: %q", b)
	}
	if !gone(rec.PID) {
		t.Error("the run is still there")
	}
}
