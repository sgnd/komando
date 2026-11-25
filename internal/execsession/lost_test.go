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
	if got := Swept("sweep-begin "+testID+"\n"+stdout+"sweep-end "+testID+"\n", testID); !slices.Equal(got, []string{a}) {
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

// Swept reads only between the markers that carry the new session's ID:
// a login banner or a profile script cannot name a session to forget.
func TestSwept(t *testing.T) {
	a, b, n := "b"+testID[1:], "c"+testID[1:], "n"+testID[1:]
	begin, end := "sweep-begin "+n+"\n", "sweep-end "+n+"\n"
	for _, tc := range []struct {
		name, stdout string
		want         []string
	}{
		{"inside the markers", begin + "swept " + a + "\nswept ../x\nnoise\n" + end, []string{a}},
		{"a banner line outside", "swept " + b + "\n" + begin + "swept " + a + "\n" + end + "swept " + b + "\n", []string{a}},
		{"only a banner", "swept " + a + "\n", nil},
		{"markers of another ID", "sweep-begin " + a + "\nswept " + b + "\nsweep-end " + a + "\n", nil},
		{"a block of another ID first", "sweep-begin " + a + "\nswept " + b + "\nsweep-end " + a + "\n" + begin + "swept " + a + "\n" + end, []string{a}},
		{"no end marker", begin + "swept " + a + "\n", nil},
		{"an ID twice", begin + "swept " + a + "\nswept " + a + "\n" + end, nil},
		{"a second block", begin + "swept " + a + "\n" + end + begin + "swept " + b + "\n" + end, []string{a}},
		{"leading space", begin + "  swept " + a + "\n" + end, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Swept(tc.stdout, n); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// A run that wrote its own end while its process still lives is not over:
// with a record, the stored process must be gone too (the run can write
// exit, killed and lost itself).
func TestRemoveScriptLiveRunThatWroteItsEnd(t *testing.T) {
	for _, mark := range []string{"exit", "killed", "lost"} {
		t.Run(mark, func(t *testing.T) {
			home := session(t, map[string]string{"out.log": "x\n", mark: "0\n"})
			text, err := RemoveScript(testID, liveRec(t, testID))
			if err != nil {
				t.Fatal(err)
			}
			if code := runSh(t, home, text); code != ExitNotRunning || !exists(sessionDir(home)) {
				t.Fatalf("exit %d, folder there: %v", code, exists(sessionDir(home)))
			}
		})
	}
	t.Run("process gone", func(t *testing.T) {
		home := session(t, map[string]string{"out.log": "x\n", "exit": "0\n"})
		text, err := RemoveScript(testID, lostRec(testID))
		if err != nil {
			t.Fatal(err)
		}
		if code := runSh(t, home, text); code != 0 || exists(sessionDir(home)) {
			t.Fatalf("exit %d, folder there: %v", code, exists(sessionDir(home)))
		}
	})
}

// The sweep skips a folder whose record names a live process, whatever
// files the run wrote; the files alone decide only without a record.
func TestSweepScriptLiveRunThatWroteItsEnd(t *testing.T) {
	home := session(t, nil)
	old := 8 * 24 * time.Hour
	live, noRecord, noStart, goneYoung := "b"+testID[1:], "c"+testID[1:], "d"+testID[1:], "e"+testID[1:]
	liveDir := sweepSession(t, home, live, old, true)
	noRecordDir := sweepSession(t, home, noRecord, old, true)
	noStartDir := sweepSession(t, home, noStart, old, true)
	goneYoungDir := sweepSession(t, home, goneYoung, time.Hour, true)
	recs := []*store.ExecSession{liveRec(t, live), {ID: noStart, PID: os.Getpid(), PGID: os.Getpid()}, lostRec(goneYoung)}
	stdout, code := runShOut(t, home, Sweep(recs))
	if code != 0 || !exists(liveDir) || exists(noRecordDir) || exists(noStartDir) {
		t.Fatalf("exit %d, live run there %v, without a record %v, record without a start %v: %s",
			code, exists(liveDir), exists(noRecordDir), exists(noStartDir), stdout)
	}
	if exists(filepath.Join(goneYoungDir, "lost")) {
		t.Fatal("a run that wrote its exit was marked lost")
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
	if got := Swept(stdout, testID); !slices.Equal(got, []string{"q" + testID[1:]}) {
		t.Fatalf("swept %v", got)
	}
	waitFile(t, home, "exit")
}
