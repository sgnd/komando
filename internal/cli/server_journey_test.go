package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The next step of a server journey is a command to copy, with the real
// names in it: exec that timed out or lost its connection → the exec that
// runs in a session, a refused fs edit → the same line with --sudo.

func TestExecTimeoutNamesExec(t *testing.T) {
	web := &store.Host{Name: "web1"}
	o := execOpts{sudo: true, dir: "/srv/app", env: []string{"MODE=full"}}
	got := execLine("exec", web, "pg_dump app | gzip > /b/app.gz", nil, o)
	want := `komando host ssh exec web1 --sudo --dir /srv/app --env MODE=full -- 'pg_dump app | gzip > /b/app.gz'`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// --sudo-user and an input file go along
	o = execOpts{sudoUser: "postgres", stdinFile: "./m.sql"}
	if got, want := execLine("exec", &store.Host{Name: "db1"}, "psql app", []byte("x"), o), `komando host ssh exec db1 --sudo-user postgres --stdin-file ./m.sql -- 'psql app'`; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	// komando's own stdin cannot be sent again, a session has no pty and
	// no Windows server runs one; module commands build their own
	// scripts: no line to copy then
	for name, c := range map[string]struct {
		name  string
		host  *store.Host
		stdin []byte
		o     execOpts
	}{
		"stdin":   {"exec", web, []byte("x"), execOpts{stdinFile: "-"}},
		"pty":     {"exec", web, nil, execOpts{pty: true}},
		"windows": {"exec", &store.Host{Name: "w", OS: store.OSWindows}, nil, execOpts{}},
		"pkg":     {"pkg.update", web, nil, execOpts{}},
		"script":  {"exec", web, nil, execOpts{display: "./deploy.sh"}},
	} {
		if got := execLine(c.name, c.host, "uptime", c.stdin, c.o); got != "" {
			t.Errorf("%s: %q, want none", name, got)
		}
	}
}

// A lost connection names the way on: --attach for a run in a session,
// the exec that starts one for a run without.
func TestLostHintNamesTheWayOn(t *testing.T) {
	at := int64(4096)
	in := &sessionRun{id: "abc", nextFrom: &at}
	e := &out.Error{Code: "CONNECTION_LOST", Hint: "check it"}
	lostHint(e, in, "web1", "komando host ssh exec web1 -- 'x'")
	if !strings.Contains(e.Hint, "`komando host ssh exec web1 --attach abc --offset 4096` reads on") || strings.Contains(e.Hint, "-- 'x'") {
		t.Errorf("in a session: %q", e.Hint)
	}
	e = &out.Error{Code: "CONNECTION_LOST", Hint: "check it"}
	lostHint(e, nil, "web1", "komando host ssh exec web1 -- 'x'")
	if !strings.Contains(e.Hint, "run it in a session, which survives a drop: `komando host ssh exec web1 -- 'x'`") {
		t.Errorf("without a session: %q", e.Hint)
	}
	e = &out.Error{Code: "TIMEOUT", Hint: "check it"}
	lostHint(e, in, "web1", "komando host ssh exec web1 -- 'x'")
	if e.Hint != "check it" {
		t.Errorf("only a lost connection: %q", e.Hint)
	}
}

func TestFsPermissionHintIsTheLineWithSudo(t *testing.T) {
	root := fsCmd()
	sub, _, err := root.Find([]string{"restore"})
	if err != nil {
		t.Fatal(err)
	}
	sub.Flags().Bool("yes", false, "the global approval flag")
	if err := sub.ParseFlags([]string{"--copy", "/etc/app.conf.bak", "--yes"}); err != nil {
		t.Fatal(err)
	}
	got := sudoRetryHint(sub, []string{"web1", "/etc/app.conf"})
	// alone, fs is the root here; under komando it reads `komando fs restore ...`
	want := "retry with --sudo: `fs restore web1 /etc/app.conf --copy /etc/app.conf.bak --sudo`"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if strings.Contains(got, "--yes") {
		t.Errorf("an approval flag is in the hint: %s", got)
	}
	// with --sudo already, retrying with it is no advice
	if err := sub.ParseFlags([]string{"--sudo"}); err != nil {
		t.Fatal(err)
	}
	if got := sudoRetryHint(sub, []string{"web1", "/etc/app.conf"}); strings.Contains(got, "retry with --sudo") {
		t.Errorf("already --sudo: %s", got)
	}
}

// exec --script that times out names the exec --script that runs the same
// script in a session.
func TestExecScriptLine(t *testing.T) {
	o := execOpts{sudo: true, scriptFlags: "--script ./deploy.sh --arg v1"}
	if got, want := execLine("exec", &store.Host{Name: "web1"}, "sh -s -- v1", []byte("body"), o), "komando host ssh exec web1 --sudo --script ./deploy.sh --arg v1"; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// exec --script in a session: the script goes on the input after the sudo
// password, into the run's private folder, and the run sends it to the
// interpreter and removes it; neither is on the command line.
func TestExecScriptOnTheWire(t *testing.T) {
	srv := startSessionServer(t, "", true)
	const pw = "hunter2-Sudo-pw"
	if err := vault.Set(store.Save(), "dev-sudo", pw); err != nil {
		t.Fatal(err)
	}
	// prod is the same server, protected: unprotect it for this change
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["dev"].SudoRef, st.Hosts["prod"].Protected = "credential:dev-sudo", false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/bash\necho deploy-marker \"$1\"\n"
	script := filepath.Join(t.TempDir(), "deploy.sh")
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = captureOutput(t, func() error {
		return runRoot(t, "host", "ssh", "exec", "dev", "--sudo", "--script", script, "--arg", "v1")
	})
	var e fakeExec
	for _, x := range srv.take() {
		if strings.Contains(x.cmd, "mkfifo") {
			e = x // the start of the session: it carries the input
			break
		}
	}
	if strings.Contains(e.cmd, pw) || strings.Contains(e.cmd, "deploy-marker") {
		t.Fatalf("the password or the script is on the command line: %s", e.cmd)
	}
	if e.stdin != pw+"\n"+body {
		t.Fatalf("stdin = %q", e.stdin)
	}
	for _, want := range []string{`cat > "$d/in"`, `{ cat "$d/in"; rm -f "$d/in"; }`, `/bin/bash -s -- `} {
		if !strings.Contains(e.cmd, want) {
			t.Fatalf("command lacks %q:\n%s", want, e.cmd)
		}
	}
}
