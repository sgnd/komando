//go:build !windows

package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sgnd/komando/internal/store"
)

// agentServer is an SSH server that, for a session that asks for agent
// forwarding, reads the keys of the client's agent back through the
// connection and answers the command with their count in its exit code.
func agentServer(t *testing.T) (string, int) {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(newSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, err := nch.Accept()
					if err != nil {
						continue
					}
					go func() {
						forwarded := false
						for r := range creqs {
							switch r.Type {
							case "auth-agent-req@openssh.com":
								forwarded = true
								r.Reply(true, nil)
							case "exec":
								r.Reply(true, nil)
								keys := 0
								if forwarded {
									if ac, areqs, err := sc.OpenChannel("auth-agent@openssh.com", nil); err == nil {
										go ssh.DiscardRequests(areqs)
										if l, err := agent.NewClient(ac).List(); err == nil {
											keys = len(l)
										}
										ac.Close()
									}
								}
								ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{uint32(keys)}))
								ch.Close()
							default:
								r.Reply(false, nil)
							}
						}
					}()
				}
			}()
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// A server with forward_agent gets this computer's ssh-agent for the
// session (the server reads one key through it); one without does not.
func TestForwardAgent(t *testing.T) {
	dialHome(t)
	keyring := agent.NewKeyring()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
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
			go agent.ServeAgent(keyring, c)
		}
	}()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", sock)
	addr, port := agentServer(t)
	for _, fwd := range []bool{true, false} {
		h := &store.Host{Name: "jump", Address: addr, Port: port, User: "u", Identity: clientKey(t), ForwardAgent: fwd}
		c, err := Dial(context.Background(), newState(h), h, Options{ConnectTimeout: 5 * time.Second, HostKeyPolicy: "accept-new"})
		if err != nil {
			t.Fatal(err)
		}
		r, err := Run(context.Background(), c, RunRequest{Command: "ssh-add -l", Timeout: 10 * time.Second, MaxOutput: 1024})
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if fwd {
			want = 1
		}
		if r.ExitCode != want {
			t.Errorf("forward_agent %v: the server saw %d keys, want %d", fwd, r.ExitCode, want)
		}
	}
}
