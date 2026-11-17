package netx

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func TestSameProgram(t *testing.T) {
	for _, c := range []struct {
		name, exe  string
		fold, want bool
	}{
		{"komando", "komando", false, true},
		{"komando-tunnel-x", "komando-tunnel-xyz-long-name", false, true}, // Linux keeps 15 characters
		{"sleep", "komando", false, false},
		{"", "komando", false, false},
		{"Komando.EXE", "komando.exe", true, true}, // Windows does not care about case
		{"Komando.EXE", "komando.exe", false, false},
		{"notepad.exe", "komando.exe", true, false},
	} {
		if got := sameProgram(c.name, c.exe, c.fold); got != c.want {
			t.Errorf("sameProgram(%q, %q, %v) = %v", c.name, c.exe, c.fold, got)
		}
	}
}

// isProgram reads the name of a running program from the system: this test
// runs on every system, Windows included, where ps does not exist.
func TestIsProgramSelf(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !isProgram(os.Getpid(), filepath.Base(self)) {
		name, err := programName(os.Getpid())
		t.Fatalf("isProgram(self, %q) = false; the system says %q (%v)", filepath.Base(self), name, err)
	}
	if isProgram(os.Getpid(), "surely-not-this-program") {
		t.Fatal("isProgram matched another program's name")
	}
}

// A session names its process by its pid, its program and when it
// started. A pid used again by another process of the same program (a
// komando or an openconnect started later) is not the session's: an old
// runtime.json put back, or a session whose process died, must not send
// its SOCKS login and its targets to whatever that process is.
func TestSessionAliveNeedsTheSameStart(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := ProcessStart(os.Getpid())
	if start == "" {
		t.Fatal("ProcessStart(self) is empty: this system's start time is not read")
	}
	if again := ProcessStart(os.Getpid()); again != start {
		t.Fatalf("ProcessStart changes: %q, then %q", start, again)
	}
	s := &store.VpnSession{PID: os.Getpid(), Exe: filepath.Base(self), ProcStart: start}
	if !SessionAlive(s) {
		t.Error("the session's own process is not alive")
	}
	s.ProcStart = "1"
	if SessionAlive(s) {
		t.Error("a process that started at another time passes as the session's")
	}
	// a session without a start time (an older komando's, or an old copy
	// of runtime.json put back) is not trusted where start times are read
	s.ProcStart = ""
	if SessionAlive(s) != !startTimesKnown {
		t.Errorf("a session without a start time: alive = %v", SessionAlive(s))
	}
	if got := ProcessStart(1 << 30); got != "" {
		t.Errorf("ProcessStart of no process = %q", got)
	}
}

// Another process started after this one has another start time.
func TestProcessStartDiffers(t *testing.T) {
	c := exec.Command(os.Args[0], "-test.run=^$")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	child := ProcessStart(c.Process.Pid)
	recorded, err := RecordStart(c.Process.Pid)
	_ = c.Wait()
	if child == "" || child == ProcessStart(os.Getpid()) || child == ProcessStart(os.Getppid()) {
		t.Errorf("a child's start %q, this process's %q, its parent's %q", child, ProcessStart(os.Getpid()), ProcessStart(os.Getppid()))
	}
	if err != nil || recorded != child {
		t.Errorf("RecordStart = %q %v, want %q", recorded, err, child)
	}
	// once it has ended, there is nothing to record
	if _, err := RecordStart(c.Process.Pid); err == nil && startTimesKnown {
		t.Error("RecordStart of an ended process: no error")
	}
}

// The start time is field 22 of Linux's /proc/PID/stat, counted after the
// program's name, which may hold spaces and brackets.
func TestStatStart(t *testing.T) {
	tail := " S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20 21\n"
	for line, want := range map[string]string{
		"42 (komando)" + tail:            "987654",
		"42 (my prog) ) (x)" + tail:      "987654", // brackets and spaces in the name
		"42 (komando) S 1 2":             "",
		"no brackets at all 1 2 3 4 5 6": "",
	} {
		if got := statStart(line); got != want {
			t.Errorf("statStart(%q) = %q, want %q", line, got, want)
		}
	}
}
