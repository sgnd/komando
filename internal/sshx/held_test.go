package sshx

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/store"
)

// heldLogin serves up (a logged-in server) on a fresh Unix socket, as
// `komando login` does, and returns its record for host.
func heldLogin(t *testing.T, up *ssh.Client, h *store.Host) *store.SSHLogin {
	t.Helper()
	dir, err := os.MkdirTemp("", "kh") // short: a Unix socket path has a small limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	key := newSigner(t)
	token := strings.Repeat("t", 48)
	go ServeHeld(ln, up, token, key, nil)
	return &store.SSHLogin{Host: h.Name, Target: TargetOf(h), Socket: sock, Token: token,
		HostKey: string(ssh.MarshalAuthorizedKey(key.PublicKey())), Until: time.Now().Add(time.Hour)}
}

func TestHeldLoginCarriesCommands(t *testing.T) {
	dialHome(t)
	up := execSSHD(t)
	// the host's own address answers nothing: only the held login reaches it
	addr, port := blackhole(t)
	h := &store.Host{Name: "web1", Address: addr, Port: port, User: "u"}
	st := newState(h)
	st.Logins = map[string]*store.SSHLogin{"web1": heldLogin(t, up, h)}
	c, err := Dial(context.Background(), st, h, Options{ConnectTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("dial through the held login: %v", err)
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Output("uptime")
	if err != nil || string(b) != "partial\n" {
		t.Fatalf("output %q, err %v", b, err)
	}
}

func TestHeldLoginNeedsItsToken(t *testing.T) {
	dialHome(t)
	h := &store.Host{Name: "web1", Address: "127.0.0.1", Port: 1, User: "u"}
	l := heldLogin(t, execSSHD(t), h)
	l.Token = strings.Repeat("x", 48)
	if c, err := dialHeld(context.Background(), l, 2*time.Second); err == nil {
		c.Close()
		t.Fatal("a wrong token logged in")
	}
}

func TestHeldLoginOnlyWhileItFits(t *testing.T) {
	h := &store.Host{Name: "web1", Address: "10.0.0.1", User: "u"}
	l := &store.SSHLogin{Host: "web1", Target: TargetOf(h), Socket: "/x", Token: "t", Until: time.Now().Add(time.Hour)}
	st := newState(h)
	st.Logins = map[string]*store.SSHLogin{"web1": l}
	if HeldFor(st, h) == nil {
		t.Fatal("a fitting login is not used")
	}
	moved := *h
	moved.Address = "10.0.0.2" // the host now points elsewhere
	if HeldFor(st, &moved) != nil {
		t.Error("a login to the old address is used")
	}
	l.Until = time.Now().Add(-time.Second)
	if HeldFor(st, h) != nil {
		t.Error("an expired login is used")
	}
}

func TestFreshDialSkipsTheHeldLogin(t *testing.T) {
	dialHome(t)
	addr, port := blackhole(t)
	h := &store.Host{Name: "web1", Address: addr, Port: port, User: "u", PasswordRef: "env:NOPE"}
	st := newState(h)
	st.Logins = map[string]*store.SSHLogin{"web1": heldLogin(t, execSSHD(t), h)}
	if c, err := Dial(context.Background(), st, h, Options{ConnectTimeout: 300 * time.Millisecond, Fresh: true}); err == nil {
		c.Close()
		t.Fatal("Fresh used the held login")
	}
}

func TestHeldJumpHostCarriesTheServerBehindIt(t *testing.T) {
	dialHome(t)
	addr, port := blackhole(t)
	bastion := &store.Host{Name: "bastion", Address: addr, Port: port, User: "u"}
	// web1 answers on loopback; it is reached through bastion's held login
	tAddr, tPort := testSSHD(t, newSigner(t))
	web1 := &store.Host{Name: "web1", Address: tAddr, Port: tPort, User: "u", Identity: clientKey(t), Via: "bastion"}
	st := newState(bastion, web1)
	up := execSSHDForwarding(t)
	st.Logins = map[string]*store.SSHLogin{"bastion": heldLogin(t, up, bastion)}
	c, err := Dial(context.Background(), st, web1, Options{ConnectTimeout: 3 * time.Second, HostKeyPolicy: "accept-new"})
	if err != nil {
		t.Fatalf("through the held jump host: %v", err)
	}
	c.Close()
}

// execSSHDForwarding is a logged-in jump host: it opens direct-tcpip
// channels (ssh -J) to loopback addresses.
func execSSHDForwarding(t *testing.T) *ssh.Client {
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
			go func() {
				defer raw.Close()
				_, chans, reqs, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					if nch.ChannelType() != "direct-tcpip" {
						_ = nch.Reject(ssh.UnknownChannelType, "no")
						continue
					}
					var p struct {
						Host  string
						Port  uint32
						OHost string
						OPort uint32
					}
					_ = ssh.Unmarshal(nch.ExtraData(), &p)
					to, err := net.Dial("tcp", net.JoinHostPort(p.Host, itoa(int(p.Port))))
					if err != nil {
						_ = nch.Reject(ssh.ConnectionFailed, err.Error())
						continue
					}
					ch, creqs, err := nch.Accept()
					if err != nil {
						to.Close()
						continue
					}
					go ssh.DiscardRequests(creqs)
					go func() { _, _ = copyClose(ch, to) }()
					go func() { _, _ = copyClose(to, ch) }()
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

func itoa(n int) string { return strconv.Itoa(n) }

func copyClose(dst io.WriteCloser, src io.Reader) (int64, error) {
	n, err := io.Copy(dst, src)
	dst.Close()
	return n, err
}
