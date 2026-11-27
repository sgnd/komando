package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// A connection that breaks while the session is read is CONNECTION_LOST
// (exit 4), with the output read before it, on each server; not a bare
// exit -1. The hint names the way on.
func TestExecConnectionLost(t *testing.T) {
	srv := startSessionServer(t, "step 1 done\n", false)
	reads := 0
	srv.answer = func(cmd string) (string, int) {
		if readID.MatchString(cmd) {
			if reads++; reads > 1 {
				return dropMark, 0
			}
		}
		out, status, _ := sessionAnswer(cmd, srv.log, false, 0)
		return out, status
	}
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
	got = strings.TrimSpace(got)
	if e := json.Unmarshal([]byte(got[strings.LastIndex(got, "\n")+1:]), &env); e != nil { // after the session's line
		t.Fatalf("%v\n%s", e, got)
	}
	if env.Error.Code != "CONNECTION_LOST" || !strings.Contains(env.Error.Hint, "session") {
		t.Fatalf("top error: %+v", env.Error)
	}
	r := env.Data.Results[0]
	if r.Error.Code != "CONNECTION_LOST" || r.Stdout != "step 1 done\n" || r.ExitCode != -1 ||
		!strings.Contains(r.Error.Message, "may still be running") {
		t.Fatalf("result: %+v", r)
	}
}

// A session run with --sudo and the server's sudo password: the password
// goes as input to a private file, never on the command line. sudo is
// first asked whether it needs one: when it does not, the file is deleted
// unread; when it does, sudo reads it before the command starts.
func TestExecSessionSudoPassword(t *testing.T) {
	srv := startSessionServer(t, "up\n", true)
	const pw = "hunter2-Sudo-pw"
	if err := vault.Set(store.Save(), "dev-sudo", pw); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(store.Save(), func(st *store.State) error { st.Hosts["dev"].SudoRef = "secret:dev-sudo"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runSession(t, "exec", "dev", "--sudo", "--read-only", "--", "uptime"); err != nil {
		t.Fatal(err)
	}
	execs := srv.take()
	if len(execs) == 0 || !strings.Contains(execs[0].cmd, "mkfifo") {
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

// The audit log has the session's start, with its ID, when the run
// starts, and the end names the same session.
func TestExecSessionAudit(t *testing.T) {
	startSessionServer(t, "up\n", true)
	first, _, err := runSession(t, "exec", "dev", "--read-only", "--", "uptime")
	if err != nil {
		t.Fatal(err)
	}
	id := first["session"]
	var recs []map[string]any
	for _, line := range strings.Split(auditText(t), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) == nil && r["session"] == id {
			recs = append(recs, r)
		}
	}
	if len(recs) != 2 || recs[0]["started"] != true || recs[1]["exit_codes"] == nil {
		t.Fatalf("audit records of session %v: %v", id, recs)
	}
}
