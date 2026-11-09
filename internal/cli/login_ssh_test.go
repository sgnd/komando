package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// twoFactorSSHD is a server that asks the password and then a one-time
// code, as a two-factor server does, and runs any command by printing it.
// logins counts the logins it took.
func twoFactorSSHD(t *testing.T) (port string, logins *atomic.Int32) {
	t.Helper()
	logins = &atomic.Int32{}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		if a, err := ask("", "", []string{"Password: "}, []bool{false}); err != nil || len(a) != 1 || a[0] != "pw" {
			return nil, errors.New("wrong password")
		}
		if a, err := ask("", "", []string{"Verification code: "}, []bool{false}); err != nil || len(a) != 1 || a[0] != "123456" {
			return nil, errors.New("wrong code")
		}
		logins.Add(1)
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, err := nch.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							if r.Type != "exec" {
								_ = r.Reply(true, nil)
								continue
							}
							_ = r.Reply(true, nil)
							var p struct{ Cmd string }
							_ = ssh.Unmarshal(r.Payload, &p)
							_, _ = ch.Write([]byte("ran on web1\n"))
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
							_ = ch.Close()
						}
					}()
				}
			}()
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, logins
}

// TestHolderChild is `komando login-holder` in the login tests: the
// background process, run from this test binary.
func TestHolderChild(t *testing.T) {
	args, ok := os.LookupEnv("KOMANDO_HOLDER_ARGS")
	if !ok {
		t.Skip("the login tests run it")
	}
	os.Args = append([]string{"komando"}, strings.Split(args, "\x1f")...)
	os.Exit(Execute())
}

// holderFromTests makes `komando login` (here, or in a pty child that has
// KOMANDO_HOLDER_FROM_TESTS) start its background process from this test
// binary.
func holderFromTests() {
	holderCommand = func(self, name string) *exec.Cmd {
		// self, not os.Args[0]: the pty child renames itself komando
		c := exec.Command(self, "-test.run=^TestHolderChild$")
		c.Env = append(os.Environ(), "KOMANDO_HOLDER_ARGS=login-holder\x1f"+name)
		return c
	}
}

func init() {
	if os.Getenv("KOMANDO_HOLDER_FROM_TESTS") != "" {
		holderFromTests()
	}
}

func TestLoginKeepsATwoFactorLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	invHome(t)
	home, err := os.MkdirTemp("", "kl") // short: the login's socket lives in it
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("KOMANDO_HOME", home)
	t.Setenv("KOMANDO_HOLDER_FROM_TESTS", "1")
	port, logins := twoFactorSSHD(t)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port)
	t.Cleanup(func() { _, _ = invRun(t, "logout", "--all") })

	// an AI agent cannot answer the code, and cannot log in for itself
	t.Setenv("KOMANDO_AGENT", "1")
	_, e := invRun(t, "exec", "web1", "--read-only", "--", "uptime")
	if e == nil || !strings.Contains(e.Hint, "komando login web1") {
		t.Fatalf("an agent without a login: %+v", e)
	}
	wantCode(t, "NEEDS_TERMINAL", "login", "web1")

	// a person logs in once, at a terminal
	os.Unsetenv("KOMANDO_AGENT")
	p := startPTY(t, "login", "web1")
	p.answer("Password: ", "pw\r")
	p.answer("Verification code: ", "123456\r")
	if code := p.exit(); code != 0 {
		t.Fatalf("login: exit %d; the screen:\n%s", code, p.shown())
	}
	p.waitFor("logged in to web1")

	// now the agent's commands use that login: no code, no new login
	t.Setenv("KOMANDO_AGENT", "1")
	for range 2 {
		d := mustRun(t, "exec", "web1", "--read-only", "--", "uptime")
		if !strings.Contains(asJSON(d), "ran on web1") {
			t.Fatalf("exec through the kept login: %v", d)
		}
	}
	if n := logins.Load(); n != 1 {
		t.Errorf("the server saw %d logins, want 1", n)
	}
	st, _ := store.Load()
	if l := st.Logins["web1"]; l == nil || time.Until(l.Until) < 7*time.Hour {
		t.Fatalf("login record %+v", l)
	}
	if rows := runningStatus(st).Logins; len(rows) != 1 || rows[0].Host != "web1" {
		t.Errorf("status: %+v", rows)
	}

	// logout ends it: the agent is back to needing a person
	mustRun(t, "logout", "web1")
	if _, e := invRun(t, "exec", "web1", "--read-only", "--", "uptime"); e == nil {
		t.Fatal("exec worked after logout")
	}
	if n := logins.Load(); n != 1 {
		t.Errorf("after logout the server saw %d logins, want 1", n)
	}
}

func TestLoginWrongCodeSaysWhy(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	invHome(t)
	home, err := os.MkdirTemp("", "kl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("KOMANDO_HOME", home)
	t.Setenv("KOMANDO_HOLDER_FROM_TESTS", "1")
	port, _ := twoFactorSSHD(t)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port)
	p := startPTY(t, "login", "web1")
	p.answer("Password: ", "pw\r")
	p.answer("Verification code: ", "000000\r")
	if code := p.exit(); code != out.ExitConnect {
		t.Fatalf("exit %d, want %d; the screen:\n%s", code, out.ExitConnect, p.shown())
	}
	p.waitFor("AUTH_FAILED")
	if st, _ := store.Load(); st.Logins["web1"] != nil {
		t.Error("a failed login was kept")
	}
}

func TestLoginCtrlCAtTheCode(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	invHome(t)
	home, err := os.MkdirTemp("", "kl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("KOMANDO_HOME", home)
	t.Setenv("KOMANDO_HOLDER_FROM_TESTS", "1")
	port, _ := twoFactorSSHD(t)
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:"+port)
	p := startPTY(t, "login", "web1")
	p.answer("Password: ", "pw\r")
	p.answer("Verification code: ", "\x03")
	if code := p.exit(); code != out.ExitError {
		t.Fatalf("exit %d, want %d; the screen:\n%s", code, out.ExitError, p.shown())
	}
	p.waitFor("interrupted")
}

func TestLoginForSetting(t *testing.T) {
	invHome(t)
	mustRun(t, "config", "set", "login_for", "2h") // shorter: fine for anyone
	wantCode(t, "USAGE", "config", "set", "login_for", "0")
	t.Setenv("KOMANDO_AGENT", "1")
	mustRun(t, "config", "set", "login_for", "1h")
	if e := wantCode(t, "SAFETY_SETTING", "config", "set", "login_for", "24h"); e.Exit != out.ExitPolicy {
		t.Errorf("exit %d", e.Exit)
	}
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
