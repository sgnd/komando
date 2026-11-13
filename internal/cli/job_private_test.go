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

// O12: a job's folder on the server and its files (command, output, pid)
// are the SSH user's alone, whatever the server's umask; the job itself
// still runs with that umask, and its environment gains no variable.
func TestJobFolderIsPrivate(t *testing.T) {
	srv := startFakeServer(t)
	// prod is the same server, protected: unprotect it for this change
	if err := store.Update(func(st *store.State) error { st.Hosts["prod"].Protected = false; return nil }); err != nil {
		t.Fatal(err)
	}
	srv.reply("4242\n")
	if err := runRoot(t, "job", "start", "dev", "--", "touch made; env > envs"); err != nil {
		t.Fatal(err)
	}
	e := srv.take()[0]

	// run what the server would have run, as a login with umask 022
	home := t.TempDir()
	c := exec.Command("/bin/sh", "-c", "umask 022; "+e.cmd)
	c.Dir, c.Env = home, []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	c.Stdin = strings.NewReader(e.stdin)
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	dirs, _ := filepath.Glob(filepath.Join(home, ".komando", "jobs", "*"))
	if len(dirs) != 1 {
		t.Fatalf("job folders: %v", dirs)
	}
	d := dirs[0]
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join(d, "exit")); err == nil {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the job did not end")
		}
	}
	if m := mode(t, d); m != 0o700 {
		t.Errorf("job folder: %04o", m)
	}
	for _, f := range []string{"cmd", "out.log", "pid", "started"} {
		if m := mode(t, filepath.Join(d, f)); m&0o077 != 0 {
			t.Errorf("%s: %04o", f, m)
		}
	}
	if m := mode(t, filepath.Join(home, "made")); m != 0o644 {
		t.Errorf("the job's own file: %04o, want the login's umask (0644)", m)
	}
	b, _ := os.ReadFile(filepath.Join(home, "envs"))
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "u=") {
			t.Errorf("the job's environment has %q", l)
		}
	}
}
