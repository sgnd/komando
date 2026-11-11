package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// testSSHD is a loopback SSH server that lets any key in and forwards
// direct-tcpip channels, so it also works as a jump host.
func testSSHD(t *testing.T, hostKey ssh.Signer) (string, int) {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(hostKey)
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
					nc.Close()
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					if nch.ChannelType() != "direct-tcpip" {
						nch.Reject(ssh.UnknownChannelType, "no")
						continue
					}
					var p struct {
						Host     string
						Port     uint32
						OrigHost string
						OrigPort uint32
					}
					if err := ssh.Unmarshal(nch.ExtraData(), &p); err != nil {
						nch.Reject(ssh.ConnectionFailed, err.Error())
						continue
					}
					tc, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
					if err != nil {
						nch.Reject(ssh.ConnectionFailed, err.Error())
						continue
					}
					ch, rq, err := nch.Accept()
					if err != nil {
						tc.Close()
						continue
					}
					go ssh.DiscardRequests(rq)
					go func() { io.Copy(ch, tc); ch.Close() }()
					go func() { io.Copy(tc, ch); tc.Close() }()
				}
			}()
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// stallingSSHD is a jump host that lets any key in and never answers a
// channel open, like a bastion waiting on a firewalled target.
func stallingSSHD(t *testing.T) (string, int) {
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
					nc.Close()
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				var held []ssh.NewChannel
				for nch := range chans {
					held = append(held, nch) // neither accepted nor rejected
				}
				_ = held
			}()
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// blackhole accepts TCP connections and never says a word.
func blackhole(t *testing.T) (string, int) {
	t.Helper()
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
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// dialHome gives a test its own komando home and no keys or agent.
func dialHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "")
	return home
}

// clientKey writes a private key file for the client.
func clientKey(t *testing.T) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newState(hosts ...*store.Host) *store.State {
	st := &store.State{Hosts: map[string]*store.Host{}, Keys: map[string]*store.Key{}, Vpns: map[string]*store.Vpn{}}
	for _, h := range hosts {
		st.Hosts[h.Name] = h
	}
	return st
}

func asOutErr(t *testing.T, err error) *out.Error {
	t.Helper()
	var oe *out.Error
	if !errors.As(err, &oe) {
		t.Fatalf("want a komando error, got %v", err)
	}
	return oe
}

// A server that accepts TCP but never sends its SSH banner must not hang
// Dial: through a jump host (an SSH channel has no deadlines) the connect
// timeout and ctx still end the handshake.
func TestHandshakeIsBounded(t *testing.T) {
	cases := []struct {
		name    string
		via     bool
		connect time.Duration
		ctx     time.Duration
		stall   bool // the jump host never answers the channel open
	}{
		{"direct, connect timeout", false, 500 * time.Millisecond, 0, false},
		{"via a jump host, connect timeout", true, 500 * time.Millisecond, 0, false},
		{"via a jump host, ctx deadline", true, time.Minute, 500 * time.Millisecond, false},
		{"via a bastion that never answers the channel open", true, 500 * time.Millisecond, 0, true},
		{"via a bastion that never answers, ctx deadline", true, time.Minute, 500 * time.Millisecond, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialHome(t)
			key := clientKey(t)
			bh, bp := testSSHD(t, newSigner(t))
			if tc.stall {
				bh, bp = stallingSSHD(t)
			}
			th, tp := blackhole(t)
			tgt := &store.Host{Name: "target", Address: th, Port: tp, User: "u", Identity: key}
			st := newState(&store.Host{Name: "bastion", Address: bh, Port: bp, User: "u", Identity: key}, tgt)
			if tc.via {
				tgt.Via = "bastion"
			}
			ctx := context.Background()
			if tc.ctx > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.ctx)
				defer cancel()
			}
			done := make(chan error, 1)
			start := time.Now()
			go func() {
				c, err := Dial(ctx, st, tgt, Options{ConnectTimeout: tc.connect, HostKeyPolicy: "off"})
				if c != nil {
					c.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("dial to a silent server succeeded")
				}
				if oe := asOutErr(t, err); oe.Code != "CONNECT_TIMEOUT" {
					t.Errorf("code %s (%s), want CONNECT_TIMEOUT", oe.Code, oe.Message)
				}
				if d := time.Since(start); d > 5*time.Second {
					t.Errorf("took %v", d)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Dial still blocked after 10s")
			}
		})
	}
}

// TestHelperProxy is the proxy program of TestProxyKeepsTheErrorCode: it
// carries stdin and stdout to KOMANDO_TEST_PROXY_ADDR.
func TestHelperProxy(t *testing.T) {
	addr := os.Getenv("KOMANDO_TEST_PROXY_ADDR")
	if addr == "" {
		t.Skip("only run as a proxy command")
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		os.Exit(3)
	}
	go func() { io.Copy(c, os.Stdin); c.Close() }()
	io.Copy(os.Stdout, c)
	os.Exit(0)
}

// A proxy command that writes to stderr must not turn a host key mismatch
// (or any other known failure) into PROXY_FAILED: agents key on the code.
func TestProxyKeepsTheErrorCode(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge := `exec "$KOMANDO_TEST_BIN" -test.run='^TestHelperProxy$'`
	cases := []struct {
		name, proxy, code, inMessage string
	}{
		{"silent proxy", bridge, "HOSTKEY_MISMATCH", ""},
		{"chatty proxy", `echo 'Starting session with SessionId: abc-123' >&2; ` + bridge, "HOSTKEY_MISMATCH", "the proxy command said: Starting session"},
		{"proxy that fails", `echo 'TargetNotConnected' >&2; exit 1`, "PROXY_FAILED", "the proxy command said: TargetNotConnected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialHome(t)
			host, port := testSSHD(t, newSigner(t))
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			if _, err := PinHostKey(addr, newSigner(t).PublicKey(), false); err != nil { // a different key
				t.Fatal(err)
			}
			t.Setenv("KOMANDO_TEST_PROXY_ADDR", addr)
			t.Setenv("KOMANDO_TEST_BIN", exe)
			h := &store.Host{Name: "web1", Address: host, Port: port, User: "u", Identity: clientKey(t), ProxyCommand: tc.proxy}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			c, err := Dial(ctx, newState(h), h, Options{ConnectTimeout: 10 * time.Second, HostKeyPolicy: "accept-new"})
			if err == nil {
				c.Close()
				t.Fatal("dial succeeded")
			}
			oe := asOutErr(t, err)
			if oe.Code != tc.code || !strings.Contains(oe.Message, tc.inMessage) {
				t.Errorf("got %s: %s (hint %q), want %s with %q", oe.Code, oe.Message, oe.Hint, tc.code, tc.inMessage)
			}
			if tc.code == "HOSTKEY_MISMATCH" && strings.Contains(oe.Hint, "proxy") {
				t.Errorf("hint is about the proxy: %q", oe.Hint)
			}
		})
	}
}

// The HOSTKEY_MISMATCH hint must not tell an agent to re-trust the key.
func TestHostKeyMismatchHintSaysReport(t *testing.T) {
	e := HostKeyMismatch("web1", "SHA256:new", []string{"SHA256:old"})
	if e.Code != "HOSTKEY_MISMATCH" || !strings.Contains(e.Hint, "report this to the user") || !strings.Contains(e.Hint, "do not re-trust") {
		t.Errorf("hint: %q", e.Hint)
	}
}

// startAgent serves an ssh-agent with one key on a unix socket and counts
// the client connections that are still open.
func startAgent(t *testing.T) *atomic.Int64 {
	t.Helper()
	dir, err := os.MkdirTemp("", "kag") // short: unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	open := new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			open.Add(1)
			go func() {
				_ = agent.ServeAgent(kr, c)
				c.Close()
				open.Add(-1)
			}()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
	return open
}

// Each hop opens its own ssh-agent connection; it is closed once the hop
// has logged in (or failed), not kept for the life of the process.
func TestAgentConnectionIsClosedAfterLogin(t *testing.T) {
	dialHome(t)
	open := startAgent(t)
	bh, bp := testSSHD(t, newSigner(t))
	th, tp := testSSHD(t, newSigner(t))
	tgt := &store.Host{Name: "target", Address: th, Port: tp, User: "u", Via: "bastion"}
	st := newState(&store.Host{Name: "bastion", Address: bh, Port: bp, User: "u"}, tgt)
	o := Options{ConnectTimeout: 5 * time.Second, HostKeyPolicy: "off"}
	for range 5 {
		c, err := Dial(context.Background(), st, tgt, o)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	refused := &store.Host{Name: "down", Address: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "u"}
	ln.Close()
	for range 5 {
		if _, err := Dial(context.Background(), st, refused, o); err == nil {
			t.Fatal("dial to a closed port succeeded")
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for open.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := open.Load(); n != 0 {
		t.Errorf("%d ssh-agent connections still open", n)
	}
}

func TestPinHostKey(t *testing.T) {
	dialHome(t)
	addr := "10.0.0.5:2222"
	old, now := newSigner(t).PublicKey(), newSigner(t).PublicKey()
	other := newSigner(t).PublicKey()
	if _, err := PinHostKey("10.0.0.6:2222", other, false); err != nil { // another server's pin stays
		t.Fatal(err)
	}
	if _, err := PinHostKey(addr, old, false); err != nil {
		t.Fatal(err)
	}
	if _, err := PinHostKey(addr, old, false); err != nil { // the same key again: no second line
		t.Fatal(err)
	}
	if pins, _ := PinnedKeys(addr); len(pins) != 1 || !SameKey(pins[0], old) {
		t.Fatalf("pins after trusting twice: %d", len(pins))
	}
	if n, err := PinHostKey(addr, now, true); err != nil || n != 1 {
		t.Fatalf("replace: removed %d, %v", n, err)
	}
	pins, _ := PinnedKeys(addr)
	if len(pins) != 1 || !SameKey(pins[0], now) {
		t.Fatalf("after replace: %d pins", len(pins))
	}
	if n, _ := PinHostKey(addr, now, true); n != 0 {
		t.Errorf("replacing a key with itself removed %d", n)
	}
	if pins, _ := PinnedKeys("10.0.0.6:2222"); len(pins) != 1 || !SameKey(pins[0], other) {
		t.Errorf("another server's pin changed")
	}
}

// FetchHostKey reads the target's key through its jump host without
// logging in to the target and without pinning it.
func TestFetchHostKeyThroughJumpHost(t *testing.T) {
	dialHome(t)
	key := clientKey(t)
	tk := newSigner(t)
	bh, bp := testSSHD(t, newSigner(t))
	th, tp := testSSHD(t, tk)
	tgt := &store.Host{Name: "target", Address: th, Port: tp, User: "u", Identity: key, Via: "bastion"}
	st := newState(&store.Host{Name: "bastion", Address: bh, Port: bp, User: "u", Identity: key}, tgt)
	got, err := FetchHostKey(context.Background(), st, tgt, Options{ConnectTimeout: 5 * time.Second, HostKeyPolicy: "accept-new"})
	if err != nil {
		t.Fatal(err)
	}
	if !SameKey(got, tk.PublicKey()) {
		t.Error("got another key")
	}
	if pins, _ := PinnedKeys(net.JoinHostPort(th, strconv.Itoa(tp))); len(pins) != 0 {
		t.Errorf("the target was pinned: %d", len(pins))
	}
	if pins, _ := PinnedKeys(net.JoinHostPort(bh, strconv.Itoa(bp))); len(pins) != 1 {
		t.Errorf("the jump host is checked as usual (accept-new pins it): %d", len(pins))
	}
}

// The ssh-agent's time starts with each request, not when the login is
// prepared: a slow transport (SSM waits up to 30s) opened in between must
// not make the agent's signature time out into a false AUTH_FAILED.
func TestAgentOutlivesASlowTransport(t *testing.T) {
	dialHome(t)
	startAgent(t)
	host, port := testSSHD(t, newSigner(t))
	h := &store.Host{Name: "web1", Address: host, Port: port, User: "u"}
	timeout := 300 * time.Millisecond
	cfg, agentConn, err := clientConfig(context.Background(), newState(h), h, Options{ConnectTimeout: timeout, HostKeyPolicy: "off"})
	if err != nil {
		t.Fatal(err)
	}
	defer agentConn.Close()
	time.Sleep(3 * timeout) // the transport takes longer than 2x the timeout to open
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	c, err := dialDirect(context.Background(), (&net.Dialer{Timeout: timeout}).DialContext, addr, cfg, 5*time.Second)
	if err != nil {
		t.Fatalf("login with the agent's key: %v", err)
	}
	c.Close()
}
