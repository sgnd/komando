package cli

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// `vpn up` on a running session never shows its SOCKS login: with it an
// agent could use the tunnel without komando's checks or audit.
func TestVpnUpHidesSocksLogin(t *testing.T) {
	invHome(t)
	t.Setenv("CLAUDECODE", "1")
	const pass = "0123456789abcdef0123456789abcdef0123456789abcdef"
	now := time.Now().UTC()
	if err := store.Update(func(st *store.State) error {
		st.Vpns["office"] = &store.Vpn{Name: "office", Kind: "anyconnect", Address: "vpn.example.test", CreatedAt: now, UpdatedAt: now}
		st.Sessions["office"] = &store.VpnSession{Vpn: "office", PID: os.Getpid(), Socks: "127.0.0.1:41234",
			SocksUser: "k1a2b3c4d5e6", SocksPass: pass, StartedAt: now, LastUsed: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"vpn", "up", "office"}, {"vpn", "up", "office", "--dry-run"}} {
		g.dryRun, g.yes, store.DryRun = false, false, false
		root := newRoot()
		root.SetArgs(append([]string{"-o", "json"}, args...))
		var buf bytes.Buffer
		saved := out.P.W
		out.P.W = &buf
		err := root.Execute()
		out.P.W = saved
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		o := buf.String()
		if !strings.Contains(o, `"already_up":true`) || !strings.Contains(o, "127.0.0.1:41234") {
			t.Errorf("%v: %s", args, o)
		}
		if strings.Contains(o, pass) || strings.Contains(o, "k1a2b3c4d5e6") || strings.Contains(o, "socks_pass") {
			t.Errorf("%v shows the SOCKS login: %s", args, o)
		}
	}
	// the state keeps it: the commands that use the session need it
	st, _ := store.Load()
	if st.Sessions["office"].SocksPass != pass {
		t.Error("the stored session lost its login")
	}
}

// the certificate checks the built-in client implements pass `vpn add`
func TestCheckOVPNCertChecks(t *testing.T) {
	for _, line := range []string{"ns-cert-type server", "remote-cert-ku a0", `remote-cert-eku "TLS Web Server Authentication"`} {
		if err := checkOVPN("client\nremote vpn.example.com 1194\n" + line + "\n"); err != nil {
			t.Errorf("%s: %v", line, err)
		}
	}
}

// a SOCKS client that never finishes the handshake is dropped after the
// handshake time; an open stream is never cut for being idle.
func TestSocksHandshakeDeadline(t *testing.T) {
	saved := socksHandshake
	socksHandshake = 200 * time.Millisecond
	t.Cleanup(func() { socksHandshake = saved })
	logger := log.New(io.Discard, "", 0)

	for _, c := range []struct {
		name, user, pass string
		send             []byte
	}{
		{"silent", "", "", nil},
		{"greeting only", "", "", []byte{5, 1, 0}},
		{"login half sent", "u", "p", []byte{5, 1, 2, 1, 1, 'u'}},
		{"request half sent", "", "", []byte{5, 1, 0, 5, 1, 0, 3, 9, 'e', 'x'}},
	} {
		t.Run(c.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				socks5Auth(server, &connMgr{}, logger, c.user, c.pass, nil)
				server.Close()
			}()
			go io.Copy(io.Discard, client)
			if len(c.send) > 0 {
				client.Write(c.send)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("socks5Auth still waits for a silent client")
			}
		})
	}

	t.Run("open stream stays", func(t *testing.T) {
		far, near := net.Pipe()
		go func() { io.Copy(far, far) }() // the target echoes
		cm := &connMgr{ctx: context.Background(), st: &store.State{}, vpnDial: func(context.Context, string, string) (net.Conn, error) { return near, nil }}
		client, server := net.Pipe()
		defer client.Close()
		go func() { socks5Auth(server, cm, logger, "", "", nil); server.Close() }()
		client.SetDeadline(time.Now().Add(5 * time.Second))
		client.Write([]byte{5, 1, 0})
		b := make([]byte, 2)
		io.ReadFull(client, b)
		client.Write([]byte{5, 1, 0, 1, 10, 0, 0, 1, 0, 22})
		rep := make([]byte, 10)
		if _, err := io.ReadFull(client, rep); err != nil || rep[1] != 0 {
			t.Fatalf("connect: %v %v", rep, err)
		}
		time.Sleep(2 * socksHandshake)
		client.Write([]byte("ping"))
		got := make([]byte, 4)
		if _, err := io.ReadFull(client, got); err != nil || string(got) != "ping" {
			t.Fatalf("an idle open stream was cut: %q %v", got, err)
		}
	})
}

// only a client that logged in counts as use of the VPN session: a local
// user who connects without the login cannot keep it from going idle
func TestSocksLoginMarksUse(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	for _, c := range []struct {
		name string
		send []byte
		used bool
	}{
		{"connect only", nil, false},
		{"no login method", []byte{5, 1, 0}, false},
		{"wrong password", []byte{5, 1, 2, 1, 1, 'u', 1, 'x'}, false},
		{"right login", []byte{5, 1, 2, 1, 1, 'u', 1, 'p'}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			client, server := net.Pipe()
			var used atomic.Bool
			done := make(chan struct{})
			go func() {
				defer close(done)
				socks5Auth(server, &connMgr{}, logger, "u", "p", func() { used.Store(true) })
				server.Close()
			}()
			go io.Copy(io.Discard, client)
			client.Write(c.send)
			client.Close()
			<-done
			if used.Load() != c.used {
				t.Errorf("used = %v, want %v", used.Load(), c.used)
			}
		})
	}
}

// flakyListener fails Accept with errs first, then gives conns, then is closed.
type flakyListener struct {
	net.Listener
	errs  []error
	conns []net.Conn
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		return nil, err
	}
	if len(l.conns) > 0 {
		c := l.conns[0]
		l.conns = l.conns[1:]
		return c, nil
	}
	return nil, net.ErrClosed
}

// an accept error such as EMFILE does not end the session; only a closed
// listener does
func TestAcceptLoopSurvivesErrors(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ln := &flakyListener{errs: []error{syscall.EMFILE, syscall.ENFILE}, conns: []net.Conn{a}}
	served := make(chan net.Conn, 1)
	done := make(chan struct{})
	go func() { acceptLoop(ln, log.New(io.Discard, "", 0), func(c net.Conn) { served <- c }); close(done) }()
	select {
	case c := <-served:
		if c != a {
			t.Fatal("served the wrong connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an accept error ended the loop")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop goes on after the listener closed")
	}
}

// sessionView, what `vpn up` prints for a new session too, drops only the
// SOCKS login and leaves the stored session as it is
func TestSessionViewHidesLogin(t *testing.T) {
	now := time.Now().UTC()
	s := &store.VpnSession{Vpn: "office", PID: 42, Socks: "127.0.0.1:41234", SocksUser: "u", SocksPass: "p", StartedAt: now, LastUsed: now}
	v := sessionView(s)
	if v.SocksUser != "" || v.SocksPass != "" {
		t.Errorf("sessionView shows the login: %+v", v)
	}
	v.SocksUser, v.SocksPass = "u", "p"
	if v != *s {
		t.Errorf("sessionView changed more than the login: %+v", v)
	}
	if s.SocksUser != "u" || s.SocksPass != "p" {
		t.Error("sessionView changed the stored session")
	}
}
