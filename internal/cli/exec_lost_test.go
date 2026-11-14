package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// A connection that breaks while the command runs is CONNECTION_LOST
// (exit 4), with the output that came before it, on each server; not a
// bare exit -1.
func TestExecConnectionLost(t *testing.T) {
	srv := startFakeServer(t)
	srv.reply("step 1 done\n", dropMark)
	var err error
	got := captureOutput(t, func() error {
		err = runRoot(t, "exec", "dev", "--read-only", "--", "uptime")
		return err
	})
	if code, ok := err.(exitCode); !ok || int(code) != 4 {
		t.Fatalf("want exit 4, got %v\n%s", err, got)
	}
	var env struct {
		Data struct {
			Results []struct {
				ExitCode int    `json:"exit_code"`
				Stdout   string `json:"stdout"`
				Error    struct {
					Code    string `json:"code"`
					Message string `json:"message"`
					Hint    string `json:"hint"`
				} `json:"error"`
			} `json:"results"`
		} `json:"data"`
		Error struct {
			Code string `json:"code"`
			Hint string `json:"hint"`
		} `json:"error"`
	}
	if e := json.Unmarshal([]byte(got), &env); e != nil {
		t.Fatalf("%v\n%s", e, got)
	}
	if env.Error.Code != "CONNECTION_LOST" || !strings.Contains(env.Error.Hint, "job start") {
		t.Fatalf("top error: %+v", env.Error)
	}
	r := env.Data.Results[0]
	if r.Error.Code != "CONNECTION_LOST" || r.Stdout != "step 1 done\n" || r.ExitCode != -1 ||
		!strings.Contains(r.Error.Message, "may still be running") {
		t.Fatalf("result: %+v", r)
	}
}

// job start --sudo works with a sudo password: it goes as input to a
// private file, never on a command line. The job first asks sudo whether
// it needs one: when it does not, the file is deleted unread; when it
// does, sudo reads it before the command starts, so the command never can.
func TestJobStartSudoPassword(t *testing.T) {
	srv := startFakeServer(t)
	const pw = "hunter2-Sudo-pw"
	if err := vault.Set(store.Save(), "dev-sudo", pw); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["dev"].SudoRef = "secret:dev-sudo"; return nil }); err != nil {
		t.Fatal(err)
	}
	srv.reply("4242\n")
	if err := runRoot(t, "job", "start", "dev", "--sudo", "--read-only", "--", "uptime"); err != nil {
		t.Fatal(err)
	}
	execs := srv.take()
	if len(execs) != 1 {
		t.Fatalf("execs: %+v", execs)
	}
	e := execs[0]
	if strings.Contains(e.cmd, pw) {
		t.Fatalf("the password is on the command line: %s", e.cmd)
	}
	if e.stdin != pw+"\n" {
		t.Fatalf("stdin = %q", e.stdin)
	}
	for _, want := range []string{`(umask 077; dd bs=1 count=16 of="$d/pw" 2>/dev/null)`, `if sudo -n sh -c : 2>/dev/null; then rm -f "$d/pw"; `,
		`{ cat "$d/pw"; rm -f "$d/pw"; `, `| sudo -S -p `} {
		if !strings.Contains(e.cmd, want) {
			t.Fatalf("command lacks %q:\n%s", want, e.cmd)
		}
	}
}

// job wait takes several IDs: one result per job, a fleet summary, and
// the worst exit code.
func TestJobWaitSeveral(t *testing.T) {
	srv := startFakeServer(t)
	if err := store.Update(store.Save(), func(st *store.State) error {
		for _, id := range []string{"j1", "j2"} {
			st.Jobs[id] = &store.Job{ID: id, Host: "dev", Command: "x", PID: 7, StartedAt: time.Now()}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv.reply("EXIT 3\n10\n100\n110\n" + statusEnd + "\n")
	var err error
	got := captureOutput(t, func() error {
		err = runRoot(t, "job", "wait", "j1", "j2", "--tail", "0")
		return err
	})
	if code, ok := err.(exitCode); !ok || int(code) != 5 {
		t.Fatalf("want exit 5, got %v\n%s", err, got)
	}
	var env struct {
		Data jobWaited `json:"data"`
	}
	if e := json.Unmarshal([]byte(got), &env); e != nil {
		t.Fatalf("%v\n%s", e, got)
	}
	if len(env.Data.Jobs) != 2 || env.Data.Summary.Failed != 2 || env.Data.Jobs[1].Error.Code != "JOB_FAILED" || env.Data.Jobs[0].Status.State != "exited" {
		t.Fatalf("%s", got)
	}
}
