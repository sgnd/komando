//go:build !windows

package execsession

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// runRead runs the read script under sh with HOME home.
func runRead(t *testing.T, home string, from int64) (string, int) {
	t.Helper()
	text, err := ReadScript(testID, from)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", text)
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	b, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(b), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), 0
}

// session makes a session folder with the given files.
func session(t *testing.T, files map[string]string) string {
	t.Helper()
	home := t.TempDir()
	d := sessionDir(home)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Dir(filepath.Dir(d)), filepath.Dir(d)} {
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for n, s := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestReadScriptRunning(t *testing.T) {
	home := session(t, map[string]string{"out.log": "one\ntwo\n"})
	text, code := runRead(t, home, 4)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, text)
	}
	st, data, err := ParseRead("motd line\n"+text, testID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Ended() || st.Size != 8 || string(data) != "two\n" {
		t.Fatalf("got %+v %q", st, data)
	}
}

func TestReadScriptEnded(t *testing.T) {
	home := session(t, map[string]string{"out.log": "x\n", "exit": "3\n", "truncated": "1024\n"})
	text, _ := runRead(t, home, 0)
	st, data, err := ParseRead(text, testID)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Ended() || st.Exit != 3 || st.Truncated != 1024 || string(data) != "x\n" {
		t.Fatalf("got %+v %q", st, data)
	}
	home = session(t, map[string]string{"out.log": "", "killed": "TERM timeout\n"})
	text, _ = runRead(t, home, 0)
	if st, _, err = ParseRead(text, testID); err != nil || !st.Ended() || st.Killed != "TERM timeout" {
		t.Fatalf("got %+v %v", st, err)
	}
}

// T5: the run can write killed itself; one that holds only spaces is no
// mark, so no reader takes a first word that is not there.
func TestReadScriptBlankKilledIsNoMark(t *testing.T) {
	home := session(t, map[string]string{"out.log": "x\n", "killed": "   \n"})
	text, _ := runRead(t, home, 0)
	st, _, err := ParseRead(text, testID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Killed != "" || st.Ended() {
		t.Fatalf("got %+v, want no killed mark and not ended", st)
	}
}

// A-499-5: on every read the folder is the login user's, a folder, not a link.
func TestReadScriptRefusesUnsafe(t *testing.T) {
	t.Run("a link", func(t *testing.T) {
		home := session(t, nil)
		real := filepath.Join(home, "real")
		if err := os.Rename(sessionDir(home), real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, sessionDir(home)); err != nil {
			t.Fatal(err)
		}
		if _, code := runRead(t, home, 0); code != ExitUnsafe {
			t.Fatalf("exit %d, want %d", code, ExitUnsafe)
		}
	})
	t.Run("a file", func(t *testing.T) {
		home := session(t, nil)
		if err := os.RemoveAll(sessionDir(home)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sessionDir(home), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, code := runRead(t, home, 0); code != ExitUnsafe {
			t.Fatalf("exit %d, want %d", code, ExitUnsafe)
		}
	})
	t.Run("a linked log", func(t *testing.T) {
		home := session(t, nil)
		other := filepath.Join(home, "other")
		if err := os.WriteFile(other, []byte("secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, filepath.Join(sessionDir(home), "out.log")); err != nil {
			t.Fatal(err)
		}
		if text, code := runRead(t, home, 0); code != ExitUnsafe {
			t.Fatalf("exit %d, want %d: %s", code, ExitUnsafe, text)
		}
	})
	t.Run("a linked sessions folder", func(t *testing.T) {
		home := session(t, nil)
		s := filepath.Dir(sessionDir(home))
		if err := os.Rename(s, s+"2"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(s+"2", s); err != nil {
			t.Fatal(err)
		}
		if _, code := runRead(t, home, 0); code != ExitUnsafe {
			t.Fatalf("exit %d, want %d", code, ExitUnsafe)
		}
	})
}

func TestReadScriptGone(t *testing.T) {
	home := session(t, nil)
	if err := os.RemoveAll(sessionDir(home)); err != nil {
		t.Fatal(err)
	}
	if _, code := runRead(t, home, 0); code != ExitGone {
		t.Fatalf("exit %d, want %d", code, ExitGone)
	}
}

func TestParseReadRefusesASecondStatus(t *testing.T) {
	two := "read-begin " + testID + "\nsize 3\nsize 9\nread-end " + testID + "\nabc"
	if _, _, err := ParseRead(two, testID); err == nil {
		t.Fatal("a second size line was taken")
	}
	if _, _, err := ParseRead("size 3\nread-end "+testID+"\nabc", testID); err == nil {
		t.Fatal("a read without its begin marker was taken")
	}
	if _, _, err := ParseRead("size 3\nabc", testID); err == nil {
		t.Fatal("a read without markers was taken")
	}
}
