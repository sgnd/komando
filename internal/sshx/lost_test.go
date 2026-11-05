package sshx

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// freezeConn stops passing bytes once frozen, like a VPN that went away
// without a word: reads wait forever, writes vanish.
type freezeConn struct {
	net.Conn
	mu     sync.Mutex
	frozen bool
	stop   chan struct{}
}

func (f *freezeConn) freeze() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.frozen {
		f.frozen = true
		close(f.stop)
	}
}

func (f *freezeConn) isFrozen() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.frozen
}

func (f *freezeConn) Read(p []byte) (int, error) {
	if f.isFrozen() {
		<-make(chan struct{})
	}
	n, err := f.Conn.Read(p)
	if f.isFrozen() {
		<-make(chan struct{})
	}
	return n, err
}

func (f *freezeConn) Write(p []byte) (int, error) {
	if f.isFrozen() {
		return len(p), nil
	}
	return f.Conn.Write(p)
}

// execSSHD runs three commands: "ok" prints and exits 0, "drop" prints a
// line and then the connection breaks, "silent" prints a line and then the
// link goes quiet.
func execSSHD(t *testing.T) *ssh.Client {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(newSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			nc := &freezeConn{Conn: raw, stop: make(chan struct{})}
			t.Cleanup(func() { raw.Close() })
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
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
							_ = r.Reply(r.Type == "exec", nil)
							if r.Type != "exec" {
								continue
							}
							var p struct{ Cmd string }
							_ = ssh.Unmarshal(r.Payload, &p)
							_, _ = ch.Write([]byte("partial\n"))
							switch p.Cmd {
							case "drop":
								time.Sleep(50 * time.Millisecond)
								raw.Close()
							case "silent":
								time.Sleep(50 * time.Millisecond)
								nc.freeze()
							default:
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{0}))
								_ = ch.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	c, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "u", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRunConnectionLost(t *testing.T) {
	for _, tc := range []struct {
		cmd    string
		silent bool
	}{{"drop", false}, {"silent", true}} {
		t.Run(tc.cmd, func(t *testing.T) {
			saved := keepaliveNS.Load()
			keepaliveNS.Store(int64(200 * time.Millisecond))
			t.Cleanup(func() { keepaliveNS.Store(saved) })
			c := &Client{Client: execSSHD(t), Host: &store.Host{Name: "web1"}}
			go keepalive(c)
			start := time.Now()
			res, err := Run(context.Background(), c, RunRequest{Command: tc.cmd, Timeout: 20 * time.Second})
			if err == nil {
				t.Fatalf("no error, result %+v", res)
			}
			e, ok := err.(*out.Error)
			if !ok || e.Code != "CONNECTION_LOST" || e.Exit != out.ExitConnect {
				t.Fatalf("want CONNECTION_LOST exit 4, got %#v", err)
			}
			if res == nil || res.Stdout != "partial\n" || res.ExitCode != -1 {
				t.Fatalf("the output before the drop is kept, exit -1: %+v", res)
			}
			if time.Since(start) > 10*time.Second {
				t.Fatalf("took %s: a silent link must be noticed long before --timeout", time.Since(start))
			}
			if c.silent.Load() != tc.silent {
				t.Fatalf("silent = %v", c.silent.Load())
			}
			for _, w := range []string{"may still be running", "web1"} {
				if !strings.Contains(e.Message, w) {
					t.Fatalf("message %q lacks %q", e.Message, w)
				}
			}
			if !strings.Contains(e.Hint, "--read-only") || !strings.Contains(e.Hint, "job start") {
				t.Fatalf("hint: %q", e.Hint)
			}
		})
	}
}

// A command that ends on its own is not "lost", and the keepalive leaves
// a healthy connection alone.
func TestRunHealthyIsNotLost(t *testing.T) {
	saved := keepaliveNS.Load()
	keepaliveNS.Store(int64(50 * time.Millisecond))
	t.Cleanup(func() { keepaliveNS.Store(saved) })
	c := &Client{Client: execSSHD(t), Host: &store.Host{Name: "web1"}}
	go keepalive(c)
	time.Sleep(300 * time.Millisecond) // a few keepalives
	res, err := Run(context.Background(), c, RunRequest{Command: "ok", Timeout: 5 * time.Second})
	if err != nil || res.ExitCode != 0 || res.Stdout != "partial\n" {
		t.Fatalf("res %+v err %v", res, err)
	}
	if c.silent.Load() {
		t.Fatal("a healthy connection was closed")
	}
}

// After the connection is gone, a new command did not start.
func TestRunAfterLossDidNotStart(t *testing.T) {
	c := &Client{Client: execSSHD(t), Host: &store.Host{Name: "web1"}}
	c.Client.Close()
	_, err := Run(context.Background(), c, RunRequest{Command: "ok", Timeout: 5 * time.Second})
	e, ok := err.(*out.Error)
	if !ok || e.Code != "CONNECTION_LOST" || !strings.Contains(e.Message, "did not run") {
		t.Fatalf("got %#v", err)
	}
}
