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
	if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["prod"].Protected = false; return nil }); err != nil {
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

// A job whose sudo refuses before it starts (no rights, a wrong password)
// left its env file (the host's env, vault values included) and its script
// in the job folder: only the job itself removed them. The wrapper now
// removes both when the job ends, whatever happened.
func TestJobLeavesNoEnvWhenSudoRefuses(t *testing.T) {
	srv := startFakeServer(t)
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["dev"].Env = map[string]string{"APP_TOKEN": "env-value-for-the-job"}
		st.Hosts["prod"].Protected = false // the same server
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv.reply("4242\n")
	script := filepath.Join(t.TempDir(), "job.sh")
	os.WriteFile(script, []byte("echo hi\n"), 0o600)
	if err := runRoot(t, "job", "start", "dev", "--sudo", "--script", script); err != nil {
		t.Fatal(err)
	}
	e := srv.take()[0]

	home := t.TempDir()
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "sudo"), []byte("#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n"), 0o700)
	c := exec.Command("/bin/sh", "-c", e.cmd)
	c.Dir, c.Env = home, []string{"HOME=" + home, "PATH=" + bin + ":/usr/bin:/bin"}
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
		if b, err := os.ReadFile(filepath.Join(d, "exit")); err == nil && len(b) > 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the job did not end")
		}
	}
	time.Sleep(200 * time.Millisecond) // the wrapper's last step
	for _, f := range []string{"env", "in", "pw"} {
		if _, err := os.Stat(filepath.Join(d, f)); !os.IsNotExist(err) {
			t.Errorf("%s stayed after sudo refused: %v", f, err)
		}
	}
}
