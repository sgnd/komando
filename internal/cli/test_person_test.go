package cli

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// A person runs `komando test` once at a terminal and answers the server's
// code; the session stays open and an agent's commands reuse it. Once it
// is ended, the agent's command fails with a message that names `test`.
func TestTestKeepsATwoFactorSession(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	invHome(t)
	home, err := os.MkdirTemp("", "kl") // short: the session's socket lives in it
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	setHome(t, home)
	t.Setenv("KOMANDO_HOLDER_FROM_TESTS", "1")
	port, logins := twoFactorSSHD(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@127.0.0.1:"+port)
	t.Cleanup(func() { _, _ = invRun(t, "test", "--end") })

	setCallerEnv(t, "KOMANDO_AGENT", "1")
	_, e := invRun(t, "host", "ssh", "exec", "web1", "--read-only", "--", "uptime")
	if e == nil || !strings.Contains(e.Hint, "`komando test web1`") || strings.Contains(e.Hint, "komando login") {
		t.Fatalf("an agent without a session: %+v", e)
	}
	if _, e := invRun(t, "test", "web1"); e == nil || e.Code != "NO_AUTH" || !strings.Contains(e.Hint, "`komando test web1`") {
		t.Fatalf("an agent's test: %+v", e)
	}

	os.Unsetenv("KOMANDO_AGENT")
	resetApproval()
	p := startPTY(t, "test", "web1")
	p.answer("Password: ", "pw\r")
	p.answer("Verification code: ", "123456\r")
	if code := p.exit(); code != 0 {
		t.Fatalf("test: exit %d; the screen:\n%s", code, p.shown())
	}
	p.waitFor("web1")

	setCallerEnv(t, "KOMANDO_AGENT", "1")
	for range 2 {
		d := mustRun(t, "host", "ssh", "exec", "web1", "--read-only", "--", "uptime")
		if !strings.Contains(asJSON(d), "ran on web1") {
			t.Fatalf("exec through the kept session: %v", d)
		}
	}
	if n := logins.Load(); n != 1 {
		t.Errorf("the server saw %d logins, want 1", n)
	}
	st, _ := store.Load()
	if l := st.Logins["web1"]; l == nil || time.Until(l.Until) < 7*time.Hour {
		t.Fatalf("session record %+v", l)
	}

	// --end on the one server ends it: the agent is back to needing a person
	mustRun(t, "host", "ssh", "test", "web1", "--end")
	if st, _ := store.Load(); st.Logins["web1"] != nil {
		t.Fatal("the session is still kept after --end")
	}
	if _, e := invRun(t, "host", "ssh", "exec", "web1", "--read-only", "--", "uptime"); e == nil || !strings.Contains(e.Hint, "`komando test web1`") {
		t.Fatalf("exec after --end: %+v", e)
	}
}

// `komando test --end` ends every kept session; with none it says so.
func TestTestEndAll(t *testing.T) {
	invHome(t)
	d := mustRun(t, "test", "--end")
	if !strings.Contains(asJSON(d), "ended") {
		t.Fatalf("test --end with no sessions: %v", d)
	}
	st, _ := store.Load()
	if st.Logins == nil {
		st.Logins = map[string]*store.SSHLogin{}
	}
	mustRun(t, "host", "ssh", "add", "web1", "u@127.0.0.1:1")
	mustRun(t, "host", "ssh", "add", "web2", "u@127.0.0.1:2")
	err := store.UpdateRuntime(tcl.storeWrite(), func(s *store.State) error {
		s.Logins["web1"] = &store.SSHLogin{Host: "web1", Until: time.Now().Add(time.Hour)}
		s.Logins["web2"] = &store.SSHLogin{Host: "web2", Until: time.Now().Add(time.Hour)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mustRun(t, "host", "ssh", "test", "web1", "--end")
	if st, _ := store.Load(); st.Logins["web1"] != nil || st.Logins["web2"] == nil {
		t.Fatalf("host test web1 --end: %v", st.Logins)
	}
	mustRun(t, "test", "--end")
	if st, _ := store.Load(); len(st.Logins) != 0 {
		t.Fatalf("test --end left %v", st.Logins)
	}
}

func TestTestNeedsATargetWithoutEnd(t *testing.T) {
	invHome(t)
	wantCode(t, "USAGE", "test")
	wantCode(t, "USAGE", "host", "ssh", "test")
}

// An AI agent's --end goes through the change-tier guard: ending the kept
// session of a protected server needs --yes, as any change there does
// (a dry run reports the stop); other servers' sessions end as before.
func TestTestEndIsGuarded(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@127.0.0.1:1", "--protected")
	mustRun(t, "host", "ssh", "add", "web2", "u@127.0.0.1:2")
	if err := store.UpdateRuntime(tcl.storeWrite(), func(s *store.State) error {
		s.Logins["web1"] = &store.SSHLogin{Host: "web1", Until: time.Now().Add(time.Hour)}
		s.Logins["web2"] = &store.SSHLogin{Host: "web2", Until: time.Now().Add(time.Hour)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	for _, args := range [][]string{{"host", "ssh", "test", "web1", "--end"}, {"test", "web1", "--end"}, {"test", "--end"}} {
		wantCode(t, "PROTECTED_TARGET", args...)
		if st, _ := store.Load(); st.Logins["web1"] == nil || st.Logins["web2"] == nil {
			t.Fatalf("%v ended a session: %v", args, st.Logins)
		}
		if d, e := invRun(t, append([]string{"--dry-run"}, args...)...); e != nil || blockedCode(d) != "PROTECTED_TARGET" {
			t.Errorf("%v --dry-run reports the stop: %v %+v", args, d, e)
		}
		setGate(tcl, false, gateDryRun)
	}
	mustRun(t, "host", "ssh", "test", "web2", "--end")
	if st, _ := store.Load(); st.Logins["web1"] == nil || st.Logins["web2"] != nil {
		t.Fatalf("host test web2 --end: %v", st.Logins)
	}
}
