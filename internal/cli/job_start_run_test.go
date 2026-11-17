//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// fakeJobServer is startFakeServer with prod (the same address as dev)
// unprotected, so a job may change dev.
func fakeJobServer(t *testing.T) *fakeServer {
	srv := startFakeServer(t)
	if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["prod"].Protected = false; return nil }); err != nil {
		t.Fatal(err)
	}
	srv.reply("1\n")
	return srv
}

// runJobHere runs what job start sent to the fake server with this
// computer's /bin/sh, as the server would, and waits until the job has an
// exit or killed file. It returns the job's folder.
func runJobHere(t *testing.T, e fakeExec) string {
	t.Helper()
	c := exec.Command("/bin/sh", "-c", e.cmd)
	c.Stdin = strings.NewReader(e.stdin)
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("start: %v\n%s", err, b)
	}
	dirs, _ := filepath.Glob(filepath.Join(os.Getenv("HOME"), ".komando", "jobs", "*"))
	if len(dirs) != 1 {
		t.Fatalf("job folders: %v", dirs)
	}
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		for _, f := range []string{"exit", "killed"} {
			if _, err := os.Stat(filepath.Join(dirs[0], f)); err == nil {
				time.Sleep(100 * time.Millisecond) // the wrapper may still be writing
				return dirs[0]
			}
		}
	}
	b, _ := os.ReadFile(filepath.Join(dirs[0], "out.log"))
	t.Fatalf("the job never ended; its log:\n%s", b)
	return ""
}

// The job's env and --stdin-file reach the command through the pipe, in
// that order, and their files are gone once sent.
func TestJobStartEnvAndInputForReal(t *testing.T) {
	srv := fakeJobServer(t)
	in := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(in, []byte("line1\nline2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runRoot(t, "job", "start", "dev", "-e", "GREETING=hi there", "--stdin-file", in, "--", `echo "$GREETING"; tr a-z A-Z`); err != nil {
		t.Fatal(err)
	}
	d := runJobHere(t, srv.take()[0])
	b, _ := os.ReadFile(filepath.Join(d, "out.log"))
	if got := string(b); got != "hi there\nLINE1\nLINE2\n" {
		t.Errorf("log %q", got)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "exit")); strings.TrimSpace(string(b)) != "0" {
		t.Errorf("exit %q", b)
	}
	for _, f := range []string{"env", "in", "pw"} {
		if _, err := os.Stat(filepath.Join(d, f)); err == nil {
			t.Errorf("%s is left in the job folder", f)
		}
	}
}

// Without --stdin-file the command reads nothing (its input ends at once)
// and the env still arrives.
func TestJobStartNoInputForReal(t *testing.T) {
	srv := fakeJobServer(t)
	if err := runRoot(t, "job", "start", "dev", "-e", "A=1", "--", `cat; echo "a=$A"`); err != nil {
		t.Fatal(err)
	}
	d := runJobHere(t, srv.take()[0])
	if b, _ := os.ReadFile(filepath.Join(d, "out.log")); string(b) != "a=1\n" {
		t.Errorf("log %q", b)
	}
}

// --timeout stops the job and notes why; it never writes an exit code.
func TestJobStartTimeoutForReal(t *testing.T) {
	srv := fakeJobServer(t)
	if err := runRoot(t, "job", "start", "dev", "--timeout", "1s", "--", "sleep 4; echo late"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	d := runJobHere(t, srv.take()[0])
	if b, _ := os.ReadFile(filepath.Join(d, "killed")); string(b) != "TERM timeout\n" {
		t.Errorf("killed %q", b)
	}
	if time.Since(start) > 3500*time.Millisecond {
		t.Errorf("stopped only after %s", time.Since(start))
	}
	time.Sleep(4 * time.Second) // what an unstopped job would print by now
	if _, err := os.Stat(filepath.Join(d, "exit")); err == nil {
		t.Error("a timed-out job wrote an exit code")
	}
	if b, _ := os.ReadFile(filepath.Join(d, "out.log")); len(b) > 0 {
		t.Errorf("the job ran on: %q", b)
	}
}
