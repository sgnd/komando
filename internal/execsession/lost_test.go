//go:build !windows

package execsession

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// liveRec is a record whose process is alive and started when it says:
// this test's own process.
func liveRec(t *testing.T, id string) *store.ExecSession {
	t.Helper()
	f := facts(t, os.Getpid())
	return &store.ExecSession{ID: id, PID: f.PID, PGID: f.PGID, ProcStart: f.Start}
}

// lostRec is a record whose process is gone: its PID now belongs to a
// process that started at another time (a reboot or an OOM kill, and the
// PID used again).
func lostRec(id string) *store.ExecSession {
	return &store.ExecSession{ID: id, PID: os.Getpid(), PGID: os.Getpid(), ProcStart: "proc 1"}
}

func runShOut(t *testing.T, home, text string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", text)
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	b, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return string(b), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), 0
}

// A run whose root died without writing exit or killed counts as ended
// once the stored process is no longer the live one (Audit A-516-1).
func TestRemoveScriptLostRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  *store.ExecSession
		exit int
		gone bool
	}{
		{"stored process gone", lostRec(testID), 0, true},
		{"stored process alive", liveRec(t, testID), ExitNotRunning, false},
		{"no record", nil, ExitNotRunning, false},
		{"another session's record", lostRec("b" + testID[1:]), ExitNotRunning, false},
		{"pid 1", &store.ExecSession{ID: testID, PID: 1, PGID: 1, ProcStart: "proc 1"}, ExitNotRunning, false},
		{"a record without a start", &store.ExecSession{ID: testID, PID: os.Getpid(), PGID: os.Getpid()}, ExitNotRunning, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := session(t, map[string]string{"out.log": "x\n"})
			text, err := RemoveScript(testID, tc.rec)
			if err != nil {
				t.Fatal(err)
			}
			if code := runSh(t, home, text); code != tc.exit || exists(sessionDir(home)) == tc.gone {
				t.Fatalf("exit %d, folder there: %v", code, exists(sessionDir(home)))
			}
		})
	}
}

func TestSweepScriptLostRun(t *testing.T) {
	home := session(t, nil)
	week := 7 * 24 * time.Hour
	a, b, c, e := "a"+testID[1:], "b"+testID[1:], "c"+testID[1:], "e"+testID[1:]
	lostOld := sweepSession(t, home, a, week+time.Hour, false)
	lostYoung := sweepSession(t, home, b, week-time.Hour, false)
	live := sweepSession(t, home, c, week+time.Hour, false)
	noRecord := sweepSession(t, home, e, week+time.Hour, false)
	stdout, code := runShOut(t, home, Sweep([]*store.ExecSession{lostRec(a), lostRec(b), liveRec(t, c)}))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if exists(lostOld) || !exists(filepath.Join(lostYoung, "lost")) {
		t.Fatalf("old lost run there: %v; young lost run marked: %v", exists(lostOld), exists(filepath.Join(lostYoung, "lost")))
	}
	if exists(filepath.Join(live, "lost")) || exists(filepath.Join(noRecord, "lost")) || !exists(noRecord) {
		t.Fatal("a live run, or one without a record, counted as lost")
	}
	if got := Swept(stdout); !slices.Equal(got, []string{a}) {
		t.Fatalf("swept %v from %q", got, stdout)
	}
}

// The lost mark is not written through a link the run left there, also
// one that points at nothing yet.
func TestSweepScriptLostMarkNotThroughALink(t *testing.T) {
	home := session(t, nil)
	a := "a" + testID[1:]
	d := sweepSession(t, home, a, time.Hour, false)
	target := filepath.Join(t.TempDir(), "made")
	if err := os.Symlink(target, filepath.Join(d, "lost")); err != nil {
		t.Fatal(err)
	}
	if _, code := runShOut(t, home, Sweep([]*store.ExecSession{lostRec(a)})); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if exists(target) {
		t.Fatal("the mark was written through the link")
	}
}

func TestSwept(t *testing.T) {
	got := Swept("swept " + testID + "\nswept ../x\nnoise\n  swept " + testID + "\n")
	if !slices.Equal(got, []string{testID}) {
		t.Fatalf("got %v", got)
	}
}

func TestReadSaysLost(t *testing.T) {
	home := session(t, map[string]string{"out.log": "x\n", "lost": ""})
	stdout, code := runRead(t, home, 0)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	st, data, err := ParseRead(stdout, testID)
	if err != nil || !st.Ended() || !st.Lost || string(data) != "x\n" {
		t.Fatalf("status %+v, data %q, err %v", st, data, err)
	}
}

// A lost mark that is a link refuses the read; a lost line with a value
// is not a read.
func TestReadLostRefusals(t *testing.T) {
	home := session(t, map[string]string{"out.log": "x\n"})
	if err := os.Symlink(filepath.Join(home, "elsewhere"), filepath.Join(sessionDir(home), "lost")); err != nil {
		t.Fatal(err)
	}
	if _, code := runRead(t, home, 0); code != ExitUnsafe {
		t.Fatalf("exit %d", code)
	}
	if _, _, err := ParseRead("read-begin "+testID+"\nlost yes\nsize 0\nread-end "+testID+"\n", testID); err == nil {
		t.Fatal("a lost line with a value was read")
	}
}

// A starting exec sweeps first, in the same call.
func TestBeginScriptSweepsThenStarts(t *testing.T) {
	home := session(t, nil)
	if err := os.Remove(sessionDir(home)); err != nil {
		t.Fatal(err)
	}
	old := sweepSession(t, home, "q"+testID[1:], 8*24*time.Hour, true)
	text, err := BeginScript(Start{ID: testID, Shown: "true", Run: startRun("true"), LogMax: 1 << 20}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stdout, code := runShOut(t, home, text)
	if code != 0 || exists(old) || !exists(sessionDir(home)) {
		t.Fatalf("exit %d, old there %v, new there %v: %s", code, exists(old), exists(sessionDir(home)), stdout)
	}
	if got := Swept(stdout); !slices.Equal(got, []string{"q" + testID[1:]}) {
		t.Fatalf("swept %v", got)
	}
	waitFile(t, home, "exit")
}
