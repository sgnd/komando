//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/sshx"
)

// A person at a terminal types the password, hidden, when komando
// connects; it is used for that command and never shown.
func TestLoginAskPersonAtTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	invHome(t)
	const pw = "terminal-Pa55"
	port, tries, _ := passwordSSHD(t, pw)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	// a first connection: the person sees the new host key, then types
	p := startPTY(t, "exec", "web1", "--read-only", "--", "uptime")
	p.answer("web1: Password: ", pw+"\r")
	if code := p.exit(); code != 0 {
		t.Fatalf("exit %d; the screen:\n%s", code, p.shown())
	}
	p.waitFor("logged in with [hidden]")
	p.waitFor("first connection to web1")
	if strings.Contains(p.shown(), pw) {
		t.Errorf("the password shows on the screen:\n%s", p.shown())
	}
	if n := tries.Load(); n != 1 {
		t.Errorf("the server got %d passwords", n)
	}
}

// tunnel start asks for the password now and hands it to the background
// process on its input: never in its arguments or environment.
func TestLoginAskTunnelStartHandsOff(t *testing.T) {
	invHome(t)
	const pw = "tunnel-Pa55"
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:2", "--login", "ask")
	setCallerEnv(t, "CLAUDECODE", "1")
	texts := loginWindow(t, pw, true, true)
	// a server komando never met: the background process could show its
	// key to nobody, so tunnel start does not ask
	e := wantCode(t, "NEEDS_PERSON", "tunnel", "start", "web1", "-L", "0:localhost:80")
	if len(*texts) != 0 || !strings.Contains(e.Hint, "`komando login web1`") {
		t.Fatalf("unknown key: %d windows, %+v", len(*texts), e)
	}
	_, _, key := passwordSSHD(t, "x")
	trustSSHD(t, "web1", "2", key)
	got := filepath.Join(t.TempDir(), "stdin")
	var args []string
	var env []string
	saved := tunnelServeCommand
	tunnelServeCommand = func(_ string, a []string) *exec.Cmd {
		args = a
		c := exec.Command("/bin/sh", "-c", "cat > \"$0\"; sleep 5", got)
		env = c.Env
		return c
	}
	t.Cleanup(func() { tunnelServeCommand = saved })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(700*time.Millisecond, cancel)
	root := newRoot(tcl)
	t.Cleanup(endCommand)
	root.SetArgs([]string{"-o", "json", "tunnel", "start", "web1", "-L", "0:localhost:80"})
	var buf bytes.Buffer
	savedW := tcl.out.W
	tcl.out.W = &buf
	_ = root.ExecuteContext(withCall(ctx, tcl))
	tcl.out.W = savedW
	if len(*texts) != 1 {
		t.Fatalf("asked %d times", len(*texts))
	}
	if !slices.Contains(args, loginsStdinFlag) || strings.Contains(strings.Join(args, " "), pw) || strings.Contains(strings.Join(env, " "), pw) {
		t.Errorf("serve args %q", args)
	}
	b, _ := os.ReadFile(got)
	want := "LOGIN " + base64.StdEncoding.EncodeToString([]byte("web1")) + " " + base64.StdEncoding.EncodeToString([]byte(pw)) + "\nEND\n"
	if !strings.HasPrefix(string(b), want) {
		t.Errorf("serve stdin %q", b)
	}
	if strings.Contains(buf.String(), pw) {
		t.Errorf("output: %s", buf.String())
	}
}

// `komando login NAME` at a terminal logs in to a login-ask server once
// (the person types the password there); an AI agent's commands then use
// that login and no window opens.
func TestLoginAskHeldLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	invHome(t)
	home, err := os.MkdirTemp("", "kl") // short: the login's socket lives in it
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	setHome(t, home)
	t.Setenv("KOMANDO_HOLDER_FROM_TESTS", "1")
	const pw = "held-Pa55"
	port, tries, _ := passwordSSHD(t, pw)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port, "--login", "ask")
	t.Cleanup(func() { _, _ = invRun(t, "logout", "--all") })
	savedAsker := sshx.Asker

	p := startPTY(t, "login", "web1")
	p.answer("Password: ", pw+"\r")
	if code := p.exit(); code != 0 {
		t.Fatalf("login: exit %d; the screen:\n%s", code, p.shown())
	}
	p.waitFor("logged in to web1")
	if strings.Contains(p.shown(), pw) {
		t.Errorf("the password shows on the screen:\n%s", p.shown())
	}

	setCallerEnv(t, "CLAUDECODE", "1")
	texts := loginWindow(t, "never-typed", true, true)
	for range 2 {
		s, err := runCache(t, "-o", "json", "exec", "web1", "--read-only", "--", "uptime")
		// (this agent's command never had the password, so it cannot hide
		// what a server prints of it: the test server echoes it)
		if err != nil || !strings.Contains(s, "logged in with") {
			t.Fatalf("exec through the kept login: %v\n%s", err, s)
		}
	}
	if len(*texts) != 0 {
		t.Errorf("the held login opened %d windows", len(*texts))
	}
	if n := tries.Load(); n != 1 {
		t.Errorf("the server got %d passwords, want 1 (the login)", n)
	}
	if fmt.Sprintf("%p", sshx.Asker) != fmt.Sprintf("%p", savedAsker) {
		t.Error("sshx.Asker was not restored")
	}
}
