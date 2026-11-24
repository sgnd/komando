//go:build !windows

package execsession

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func runSh(t *testing.T, home, text string) int {
	t.Helper()
	cmd := exec.Command("sh", "-c", text)
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	b, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return 0
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestRemoveScript(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		exit  int
		gone  bool
	}{
		{"ended", map[string]string{"out.log": "x\n", "exit": "0\n"}, 0, true},
		{"stopped", map[string]string{"out.log": "x\n", "killed": "TERM stop\n"}, 0, true},
		{"running", map[string]string{"out.log": "x\n"}, ExitNotRunning, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := session(t, tc.files)
			text, err := RemoveScript(testID, nil)
			if err != nil {
				t.Fatal(err)
			}
			if code := runSh(t, home, text); code != tc.exit || exists(sessionDir(home)) == tc.gone {
				t.Fatalf("exit %d, folder there: %v", code, exists(sessionDir(home)))
			}
		})
	}
	if _, err := RemoveScript("../x", nil); err == nil {
		t.Fatal("a bad ID was taken")
	}
}

func TestRemoveScriptRefusesALink(t *testing.T) {
	home := session(t, map[string]string{"exit": "0\n"})
	other := t.TempDir()
	keep := filepath.Join(other, "keep")
	if err := os.WriteFile(keep, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := filepath.Dir(sessionDir(home))
	if err := os.RemoveAll(s); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, s); err != nil {
		t.Fatal(err)
	}
	text, _ := RemoveScript(testID, nil)
	if code := runSh(t, home, text); code != ExitUnsafe || !exists(keep) {
		t.Fatalf("exit %d through a linked sessions folder", code)
	}
}

// sweepSession makes a session folder named id that started age ago.
func sweepSession(t *testing.T, home, id string, age time.Duration, ended bool) string {
	t.Helper()
	d := filepath.Join(home, ".komando", "sessions", id)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	started := strconv.FormatInt(time.Now().Add(-age).Unix(), 10)
	if err := os.WriteFile(filepath.Join(d, "started"), []byte(started+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ended {
		if err := os.WriteFile(filepath.Join(d, "exit"), []byte("0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestSweepScript(t *testing.T) {
	home := session(t, nil)
	week := 7 * 24 * time.Hour
	old := sweepSession(t, home, "a"+testID[1:], week+time.Hour, true)
	running := sweepSession(t, home, "b"+testID[1:], week+time.Hour, false)
	young := sweepSession(t, home, "c"+testID[1:], week-time.Hour, true)
	other := sweepSession(t, home, "notasession", week+time.Hour, true)
	if code := runSh(t, home, Sweep(nil)); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if exists(old) || !exists(running) || !exists(young) || !exists(other) {
		t.Fatalf("old gone %v, running %v, young %v, other name %v", !exists(old), exists(running), exists(young), exists(other))
	}
}

func TestSweepScriptSkipsALinkedSession(t *testing.T) {
	home := session(t, nil)
	elsewhere := sweepSession(t, t.TempDir(), "x", 8*24*time.Hour, true)
	link := filepath.Join(home, ".komando", "sessions", "d"+testID[1:])
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	if code := runSh(t, home, Sweep(nil)); code != 0 || !exists(filepath.Join(elsewhere, "exit")) || !exists(link) {
		t.Fatalf("exit %d; the link or the linked folder's files are gone", code)
	}
}

func TestSweepScriptNoSessions(t *testing.T) {
	if code := runSh(t, t.TempDir(), Sweep(nil)); code != 0 {
		t.Fatalf("exit %d without a sessions folder", code)
	}
}
