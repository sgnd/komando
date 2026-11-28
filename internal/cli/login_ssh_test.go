package cli

import (
	"bufio"
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

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// twoFactorSSHD is a server that asks the password and then a one-time
// code, as a two-factor server does, and runs any command by printing it.
// logins counts the logins it took.
func twoFactorSSHD(t *testing.T) (port string, logins *atomic.Int32) {
	t.Helper()
	port, logins, _ = twoFactorSSHDCount(t)
	return port, logins
}

// serverSaw is what a fake server was sent: connections reached it, and
// tries are the passwords and codes it was asked to check.
type serverSaw struct{ conns, tries atomic.Int32 }

// twoFactorSSHDCount is twoFactorSSHD that also counts what reached it.
func twoFactorSSHDCount(t *testing.T) (port string, logins *atomic.Int32, saw *serverSaw) {
	t.Helper()
	logins, saw = &atomic.Int32{}, &serverSaw{}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		saw.tries.Add(1)
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
			saw.conns.Add(1)
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
							const ran = "ran on web1\n"
							o, _, ok := sessionAnswer(p.Cmd, ran, true, 0)
							if !ok {
								o = ran
							}
							_, _ = ch.Write([]byte(o))
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
							_ = ch.Close()
						}
					}()
				}
			}()
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, logins, saw
}

// TestHolderChild is `komando login-holder` in the kept-session tests: the
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

// A wrong code at `komando test` says why and keeps no session.
func TestTestWrongCodeSaysWhy(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	invHome(t)
	home, err := os.MkdirTemp("", "kl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	setHome(t, home)
	t.Setenv("KOMANDO_HOLDER_FROM_TESTS", "1")
	port, _ := twoFactorSSHD(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@127.0.0.1:"+port)
	p := startPTY(t, "test", "web1")
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

// Ctrl-C at the code of `komando test` stops it and keeps no session.
func TestTestCtrlCAtTheCode(t *testing.T) {
	if testing.Short() {
		t.Skip("starts processes")
	}
	invHome(t)
	home, err := os.MkdirTemp("", "kl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	setHome(t, home)
	t.Setenv("KOMANDO_HOLDER_FROM_TESTS", "1")
	port, _ := twoFactorSSHD(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@127.0.0.1:"+port)
	p := startPTY(t, "test", "web1")
	p.answer("Password: ", "pw\r")
	p.answer("Verification code: ", "\x03")
	if code := p.exit(); code != out.ExitError {
		t.Fatalf("exit %d, want %d; the screen:\n%s", code, out.ExitError, p.shown())
	}
	p.waitFor("Stopped (Ctrl-C)")
}

func TestLoginForSetting(t *testing.T) {
	invHome(t)
	mustRun(t, "config", "set", "login_for", "2h") // shorter: fine for anyone
	wantCode(t, "USAGE", "config", "set", "login_for", "0")
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	mustRun(t, "config", "set", "login_for", "1h")
	if e := wantCode(t, "SAFETY_SETTING", "config", "set", "login_for", "24h"); e.Exit != out.ExitPolicy {
		t.Errorf("exit %d", e.Exit)
	}
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// login-holder's input comes only from `komando test`: anything else on
// it (by hand, or a broken line) is one answer, NEEDS_PERSON, never a
// parse error that reads as a failed login.
func TestHolderStdinNotByHand(t *testing.T) {
	tok := strings.Repeat("a", 32)
	for _, in := range []string{
		"",
		"TOKEN " + tok + "\nUNTIL soon\nPASS \n",
		"TOKEN " + tok + "\nUNTIL 1\nPASS !!notbase64\n",
		"TOKEN short\nUNTIL 1\nPASS \n",
	} {
		_, _, err := holderStdin(bufio.NewReader(strings.NewReader(in)))
		e, ok := err.(*out.Error)
		if !ok || e.Code != "NEEDS_PERSON" {
			t.Errorf("%q: %v", in, err)
		}
	}
	if tk, _, err := holderStdin(bufio.NewReader(strings.NewReader("TOKEN " + tok + "\nUNTIL 1\nPASS \n"))); err != nil || tk != tok {
		t.Errorf("good input: %q %v", tk, err)
	}
}
