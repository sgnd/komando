//go:build !windows

package execsession

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// in wraps facts in the markers that carry the session ID.
func in(id, body string) string { return "facts-begin " + id + "\n" + body + "facts-end " + id + "\n" }

func TestParseFacts(t *testing.T) {
	got, err := ParseFacts(in(testID, "pid 41\npgid 41\nstart proc 12345\n"), testID)
	if err != nil || got != (Facts{PID: 41, PGID: 41, Start: "proc 12345"}) {
		t.Fatalf("%+v, %v", got, err)
	}
	// lines outside the markers are someone else's (a login banner, a
	// profile script): never read as facts
	got, err = ParseFacts("pid 99\npgid 99\nstart proc 1\n"+in(testID, "pid 7\npgid 3\nstart ps Mon Nov 24 14:06:00 2026\n")+"pid 98\n", testID)
	if err != nil || got != (Facts{PID: 7, PGID: 3, Start: "ps Mon Nov 24 14:06:00 2026"}) {
		t.Fatalf("%+v, %v", got, err)
	}
	other := strings.Repeat("b", 52)
	for _, bad := range []string{
		"",
		"pid 41\npgid 41\nstart proc 1\n", // no markers
		in(other, "pid 41\npgid 41\nstart proc 1\n"),                  // another session's markers
		in(testID, "pid 41\npgid 41\nstart proc 1\npid 42\n"),         // a second pid
		in(testID, "pid 41\npgid 41\npgid 42\nstart proc 1\n"),        // a second pgid
		in(testID, "pid 41\npgid 41\nstart proc 1\nstart proc 2\n"),   // a second start
		"facts-begin " + testID + "\npid 41\npgid 41\nstart proc 1\n", // no end
		in(testID, "pid 41\npgid 41\n"),                               // no start
		in(testID, "pid 41\nstart proc 1\n"),                          // no pgid
		in(testID, "pid x\npgid 1\nstart ps a\n"),                     // not a number
		in(testID, "pid 1\npgid 1\nstart proc 5\n"),
		in(testID, "pid 0\npgid 9\nstart proc 5\n"),
		in(testID, "pid 9\npgid 1\nstart proc 5\n"),
		in(testID, "pid -9\npgid 9\nstart proc 5\n"),
	} {
		if f, err := ParseFacts(bad, testID); err == nil {
			t.Errorf("%q: %+v, want an error", bad, f)
		}
	}
}

// startGroup starts `sh -c 'sleep 60 & echo $!; wait'`, as the leader of
// its own process group when ownGroup, and gives the shell and the sleep
// child. Both are ended and reaped when the test ends.
func startGroup(t *testing.T, ownGroup bool) (leader, child int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", `sleep 60 & echo $!; wait`)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: ownGroup}
	outp, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, _ := outp.Read(buf)
	child, err = strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = syscall.Kill(child, syscall.SIGKILL)
		_ = cmd.Process.Kill()
		<-done
	})
	return cmd.Process.Pid, child
}

// gone waits up to 5 s for pid to be gone (a zombie counts as gone: its
// parent has not reaped it yet).
func gone(pid int) bool {
	for range 50 {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		if b, _ := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output(); strings.HasPrefix(strings.TrimSpace(string(b)), "Z") {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func facts(t *testing.T, pid int) Facts {
	t.Helper()
	b, err := exec.Command("sh", "-c", FactsScript+`; ks_facts `+strconv.Itoa(pid)+` `+testID).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	f, err := ParseFacts(string(b), testID)
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return f
}

// The facts of a live process: its PID, its group, and a start that stays
// the same when read again (on Linux from /proc, elsewhere from ps).
func TestFactsScript(t *testing.T) {
	leader, _ := startGroup(t, true)
	f := facts(t, leader)
	if f.PID != leader || f.PGID != leader {
		t.Errorf("%+v, want pid and pgid %d", f, leader)
	}
	want := "ps "
	if _, err := os.Stat("/proc/self/stat"); err == nil {
		want = "proc "
	}
	if !strings.HasPrefix(f.Start, want) || len(f.Start) <= len(want) {
		t.Errorf("start %q, want it to begin %q", f.Start, want)
	}
	time.Sleep(1100 * time.Millisecond)
	if again := facts(t, leader); again.Start != f.Start {
		t.Errorf("start read again: %q, first %q", again.Start, f.Start)
	}
	if runtime.GOOS == "linux" && want != "proc " {
		t.Error("Linux without /proc")
	}
}

func TestFactsScriptGoneProcess(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	b, _ := exec.Command("sh", "-c", FactsScript+`; ks_start `+strconv.Itoa(cmd.Process.Pid)).CombinedOutput()
	if strings.TrimSpace(string(b)) != "" {
		t.Errorf("a gone process has a start: %q", b)
	}
}
