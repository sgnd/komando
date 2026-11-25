package execsession

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// startRecordPS starts s with %LOCALAPPDATA% at base and gives the record
// a start on this computer keeps.
func startRecordPS(t *testing.T, base string, s StartPS) *store.ExecSession {
	t.Helper()
	got, code := runStartPS(t, base, s)
	f, err := ReadStartPS("web1", code, got, "", s.ID)
	if err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	return &store.ExecSession{ID: s.ID, Host: "web1", PID: f.PID, ProcStart: f.Start, Image: f.Image, CmdLine: f.CmdLine}
}

func runAt(t *testing.T, base, script string) (string, int) {
	t.Helper()
	return psRunFile(t, script, nil, []string{"LOCALAPPDATA=" + base})
}

func alive(t *testing.T, pid int) bool {
	t.Helper()
	o, _ := psRunFile(t, "@(Get-CimInstance -ClassName Win32_Process -Filter 'ProcessId = "+strconv.Itoa(pid)+"').Count\n", nil, nil)
	return strings.TrimSpace(o) == "1"
}

// W6 in part: the stop refuses a record whose creation date differs (the
// process lives on), then ends the run's whole tree, a child it started
// included, notes the stop, and a second stop finds nothing to stop.
func TestStopPSOnWindows(t *testing.T) {
	base := t.TempDir()
	s := psStart()
	s.Env, s.Stdin = nil, nil
	s.Command = "Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile', '-Command', 'Start-Sleep 120'; Start-Sleep 120"
	rec := startRecordPS(t, base, s)
	time.Sleep(3 * time.Second)

	other := *rec
	other.ProcStart = "cim 2000-01-01T00:00:00.0000000Z"
	script, err := StopScriptPS(&other)
	if err != nil {
		t.Fatal(err)
	}
	if o, code := runAt(t, base, script); code != ExitNotRunning || !alive(t, rec.PID) {
		t.Fatalf("a record with another creation date: exit %d, %s", code, o)
	}

	script, err = StopScriptPS(rec)
	if err != nil {
		t.Fatal(err)
	}
	o, code := runAt(t, base, script)
	pids, err := ParseStopPS(o, rec.ID)
	if code != 0 || err != nil || len(pids) < 3 {
		t.Fatalf("exit %d, %v, pids %v: %s", code, err, pids, o)
	}
	time.Sleep(time.Second)
	for _, p := range pids {
		if alive(t, p) {
			t.Errorf("process %d is still there after the stop", p)
		}
	}
	if k, _ := os.ReadFile(filepath.Join(sessionDirPS(base), "killed")); string(k) != "stop" {
		t.Errorf("killed %q", k)
	}
	if _, code := runAt(t, base, script); code != ExitNotRunning {
		t.Errorf("a second stop: exit %d", code)
	}
}

// W9 in part: remove refuses a running session, deletes an ended one, and
// a junction inside the folder is removed without what it points to.
func TestRemovePSOnWindows(t *testing.T) {
	base := t.TempDir()
	s := psStart()
	s.Env, s.Stdin = nil, nil
	s.Command = "Start-Sleep 120"
	rec := startRecordPS(t, base, s)
	rm, err := RemoveScriptPS(rec.ID, rec)
	if err != nil {
		t.Fatal(err)
	}
	if o, code := runAt(t, base, rm); code != ExitNotRunning {
		t.Fatalf("remove of a running session: exit %d, %s", code, o)
	}
	stop, _ := StopScriptPS(rec)
	if o, code := runAt(t, base, stop); code != 0 {
		t.Fatalf("stop: exit %d, %s", code, o)
	}
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if o, code := psRunFile(t, "param([string]$l, [string]$t)\n$null = New-Item -ItemType Junction -Path $l -Target $t\n", nil, nil,
		filepath.Join(sessionDirPS(base), "j"), outside); code != 0 {
		t.Fatalf("junction: %s", o)
	}
	if o, code := runAt(t, base, rm); code != 0 {
		t.Fatalf("remove of an ended session: exit %d, %s", code, o)
	}
	if _, err := os.Stat(sessionDirPS(base)); !os.IsNotExist(err) {
		t.Error("the session folder is still there")
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Errorf("remove followed the junction: %v", err)
	}
}

// W9 in part: the sweep deletes an ended session older than 7 days by the
// server's clock and nothing else, and a running session is never swept.
func TestSweepPSOnWindows(t *testing.T) {
	base := t.TempDir()
	old, fresh, running := psStart(), psStart(), psStart()
	fresh.ID, running.ID = strings.Repeat("b", 52), strings.Repeat("c", 52)
	for _, s := range []*StartPS{&old, &fresh, &running} {
		s.Env, s.Stdin = nil, nil
	}
	running.Command = "Start-Sleep 120"
	startRecordPS(t, base, old)
	startRecordPS(t, base, fresh)
	rec := startRecordPS(t, base, running)
	sessions := filepath.Join(base, "komando", "sessions")
	waitFilePS(t, filepath.Join(sessions, old.ID), "exit")
	waitFilePS(t, filepath.Join(sessions, fresh.ID), "exit")
	for _, id := range []string{old.ID, running.ID} {
		if err := os.WriteFile(filepath.Join(sessions, id, "started"), []byte("1000000000"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	o, code := runAt(t, base, "Write-Output 'sweep-begin x'\n"+SweepPS([]*store.ExecSession{rec})+"Write-Output 'sweep-end x'\n")
	if code != 0 || strings.Join(Swept(o, "x"), " ") != old.ID {
		t.Fatalf("exit %d, swept %v: %s", code, Swept(o, "x"), o)
	}
	for _, id := range []string{fresh.ID, running.ID} {
		if _, err := os.Stat(filepath.Join(sessions, id)); err != nil {
			t.Errorf("%s was swept: %v", id, err)
		}
	}
	stop, _ := StopScriptPS(rec)
	runAt(t, base, stop)
}

// A-450-1 on a real PowerShell: a %LOCALAPPDATA% with & in it (a user
// named a&b) is refused by the start, the remove and the sweep, and no
// rmdir runs: the planted session folder is still there.
func TestMetaPathRefusedOnWindows(t *testing.T) {
	base := filepath.Join(t.TempDir(), "a&b")
	dir := sessionDirPS(base)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"exit": "0", "started": "1000000000"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rm, err := RemoveScriptPS(testID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o, code := runAt(t, base, rm); code != ExitUnsafe {
		t.Fatalf("remove: exit %d, want %d: %s", code, ExitUnsafe, o)
	}
	o, code := runAt(t, base, "Write-Output 'sweep-begin x'\n"+SweepPS(nil)+"Write-Output 'sweep-end x'\n")
	if got := Swept(o, "x"); code != 0 || len(got) != 0 {
		t.Fatalf("sweep: exit %d, swept %v: %s", code, got, o)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("a refused path was deleted from: %v", err)
	}
	if o, code := runStartPS(t, base, psStart()); code != ExitNoFolder || !strings.Contains(o, "unsafe-path") {
		t.Errorf("start: exit %d: %s", code, o)
	}
}
