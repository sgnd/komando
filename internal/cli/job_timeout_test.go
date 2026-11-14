package cli

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// A job stopped by job start --timeout says so: status has timed_out and
// the signal alone, and job wait names the --timeout, not job kill.
func TestJobStatusTimedOut(t *testing.T) {
	srv := startFakeServer(t)
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Jobs["j1"] = &store.Job{ID: "j1", Host: "dev", Command: "sleep 99", PID: 7, StartedAt: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv.reply("KILLED TERM timeout\n10\n100\n160\n" + statusEnd + "\n")
	d := mustRun(t, "job", "status", "j1")
	if d["state"] != "killed" || d["signal"] != "TERM" || d["timed_out"] != true {
		t.Errorf("status %v", d)
	}
	srv.reply("KILLED TERM timeout\n10\n100\n160\n" + statusEnd + "\n")
	got := captureOutput(t, func() error { return runRoot(t, "job", "wait", "j1", "--tail", "0") })
	if !strings.Contains(got, `"JOB_KILLED"`) || !strings.Contains(got, "stopped by its --timeout") || strings.Contains(got, "stopped with `komando job kill`") {
		t.Errorf("wait: %s", got)
	}
	if got := (&jobStatus{State: "killed", Signal: "TERM", TimedOut: true, RuntimeSec: 60}).describe(); !strings.HasPrefix(got, "stopped by its --timeout") {
		t.Errorf("text %q", got)
	}
	srv.reply("KILLED KILL\n10\n100\n160\n" + statusEnd + "\n")
	if d := mustRun(t, "job", "status", "j1"); d["signal"] != "KILL" || d["timed_out"] != nil {
		t.Errorf("job kill: %v", d)
	}
}

// --sudo-user implies sudo (as exec), --stdin-file does not go with
// --script, and the dry run names the input, the user and the limit.
func TestJobStartNewFlags(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "root@10.0.0.5")
	in := t.TempDir() + "/in.sql"
	if err := os.WriteFile(in, []byte("select 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := mustRun(t, "job", "start", "web1", "--sudo-user", "postgres", "--stdin-file", in, "--timeout", "90m", "--dry-run", "--", "psql app")
	if d["sudo_user"] != "postgres" || d["stdin_bytes"] != float64(10) || d["timeout_seconds"] != float64(5400) {
		t.Errorf("dry run: %v", d)
	}
	wantCode(t, "USAGE", "job", "start", "web1", "--script", in, "--stdin-file", in)
	wantCode(t, "FILE_NOT_FOUND", "job", "start", "web1", "--stdin-file", in+".none", "--", "cat")
}
