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

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
)

// `vpn up` on a running session never shows its SOCKS login: with it an
// agent could use the tunnel without komando's checks or audit.
func TestVpnUpHidesSocksLogin(t *testing.T) {
	invHome(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	const pass = "0123456789abcdef0123456789abcdef0123456789abcdef"
	now := time.Now().UTC()
	if err := store.Update(store.Save, func(st *store.State) error {
		st.Vpns["office"] = &store.Vpn{Name: "office", Kind: "anyconnect", Address: "vpn.example.test", CreatedAt: now, UpdatedAt: now}
		st.Sessions["office"] = &store.VpnSession{Vpn: "office", PID: os.Getpid(), Socks: "127.0.0.1:41234",
			SocksUser: "k1a2b3c4d5e6", SocksPass: pass, StartedAt: now, LastUsed: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"vpn", "up", "office"}, {"vpn", "up", "office", "--dry-run"}} {
		tcl.flags.dryRun, tcl.flags.yes = false, false
		root := newRoot(tcl)
		t.Cleanup(endCommand) // the next test starts with none of this command's flags
		root.SetArgs(append([]string{"-o", "json"}, args...))
		var buf bytes.Buffer
		saved := tcl.out.W
		tcl.out.W = &buf
		err := root.Execute()
		tcl.out.W = saved
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
				socks5Auth(server, &connMgr{cl: tcl}, logger, c.user, c.pass, nil)
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
		cm := &connMgr{cl: tcl, ctx: context.Background(), st: &store.State{}, vpnDial: func(context.Context, string, string) (net.Conn, error) { return near, nil }}
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
				socks5Auth(server, &connMgr{cl: tcl}, logger, "u", "p", func() { used.Store(true) })
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

// A VPN that needs a person: the dry run says the real run stops, and the
// real run is in the audit log as failed.
func TestVpnUpNeedsPersonDryRunAndAudit(t *testing.T) {
	invHome(t)
	noAgent(t)
	now := time.Now().UTC()
	if err := store.Update(store.Save, func(st *store.State) error {
		st.Vpns["client-x"] = &store.Vpn{Name: "client-x", Kind: "anyconnect", Portal: "vpn.example.test", MFA: true, CreatedAt: now, UpdatedAt: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	d := mustRun(t, "vpn", "up", "client-x", "--dry-run")
	meta, _ := d["_meta"].(map[string]any)
	if b, _ := meta["would_be_blocked"].(map[string]any); d["would_connect"] != false || b["code"] != "VPN_LOGIN_REQUIRED" {
		t.Errorf("dry run: %v", d)
	}
	wantCode(t, "VPN_LOGIN_REQUIRED", "vpn", "up", "client-x")
	a := mustRun(t, "audit", "--command", "vpn.up")
	var real []map[string]any
	for _, e := range a["entries"].([]any) {
		if m := e.(map[string]any); m["dry_run"] == false {
			real = append(real, m)
		}
	}
	if len(real) != 1 || real[0]["ok"] != false || real[0]["error"] != "VPN_LOGIN_REQUIRED" {
		t.Errorf("audit: %v", real)
	}
}

func TestNeedsPersonLogin(t *testing.T) {
	for v, want := range map[*store.Vpn]bool{
		{Kind: "wireguard"}:                           false,
		{Kind: "globalprotect", MFA: true}:            true,
		{Kind: "l2tp", User: "budi"}:                  true,
		{Kind: "l2tp", User: "budi", KeyRef: "x"}:     false,
		{Kind: "openvpn", User: "budi", OSMode: true}: false,
	} {
		if needsPersonLogin(v) != want {
			t.Errorf("%+v: want %v", *v, want)
		}
	}
}

// vpn edit: -g and -t add, as in host edit; --portal and --ca change a VPN
// of a kind that has them.
func TestVpnEditFlags(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "add", "v1", "socks", "--proxy-address", "127.0.0.1:1080", "-g", "a", "-t", "x")
	mustRun(t, "vpn", "edit", "v1", "-g", "b", "-t", "y")
	st, _ := store.Load()
	if v := st.Vpns["v1"]; strings.Join(v.Groups, ",") != "a,b" || strings.Join(v.Tags, ",") != "x,y" {
		t.Errorf("-g/-t add: %v %v", v.Groups, v.Tags)
	}
	mustRun(t, "vpn", "edit", "v1", "--rm-group", "a", "--rm-tag", "x")
	st, _ = store.Load()
	if v := st.Vpns["v1"]; strings.Join(v.Groups, ",") != "b" || strings.Join(v.Tags, ",") != "y" {
		t.Errorf("--rm-group/--rm-tag: %v %v", v.Groups, v.Tags)
	}
	wantCode(t, "USAGE", "vpn", "edit", "v1", "-g", "c", "--rm-group", "c")
	wantCode(t, "USAGE", "vpn", "edit", "v1", "--portal", "vpn.example.com")

	mustRun(t, "vpn", "add", "client-x", "globalprotect", "--portal", "vpn.example.com")
	mustRun(t, "vpn", "edit", "client-x", "--portal", "gw1.example.com")
	st, _ = store.Load()
	if p := st.Vpns["client-x"].Portal; p != "gw1.example.com" {
		t.Errorf("--portal: %q", p)
	}
	wantCode(t, "USAGE", "vpn", "edit", "client-x", "--portal", "-x")
	wantCode(t, "USAGE", "vpn", "edit", "client-x", "--ca", "/nonexistent")
}

// An alias names the command it stands for in every envelope, its
// errors too.
func TestAliasEnvelopeName(t *testing.T) {
	root := newRoot(tcl)
	for path, want := range map[string]string{"vpn test": "test", "host list": "list", "vpn add": "vpn.add"} {
		c, _, err := root.Find(strings.Fields(path))
		if err != nil {
			t.Fatal(err)
		}
		if got := envelopeName(c); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}

// vpn add reads as host add: what happened first, the config indented,
// notes last; the next command is on stderr (S-9.3).
func TestVpnChangeText(t *testing.T) {
	v := &store.Vpn{Name: "office", Kind: "wireguard", KeyRef: "secret:office-key", Config: "[Interface]\nAddress = 10.66.0.2/32\n", Groups: []string{"a"}}
	got := vpnChangeText{verb: "added", v: v, notes: []string{"n1"}}.Text()
	want := "added office\n  kind: wireguard\n  private key: secret:office-key\n  groups: a\n  config:\n    [Interface]\n    Address = 10.66.0.2/32\nnote: n1"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if got := (vpnChangeText{verb: "would change", v: v}).Text(); !strings.HasPrefix(got, "would change office (dry run)\n") {
		t.Errorf("dry run: %s", got)
	}
	// a weaker login a person allowed shows in the text too
	weak := &store.Vpn{Name: "kantor", Kind: "l2tp", Server: "vpn.kantor.id", LegacyCrypto: true, AllowPAP: true}
	if got := (vpnChangeText{verb: "changed", v: weak}).Text(); !strings.Contains(got, "legacy crypto: yes") || !strings.Contains(got, "allow PAP: yes") {
		t.Errorf("weaker login: %s", got)
	}
}

// TestVpnTestProxyMustAnswer: `vpn test` and `vpn up` of a SOCKS or HTTP
// proxy without --check connect to the proxy itself; they said ok for a
// proxy that does not answer, while `vpn status` said it was down.
func TestVpnTestProxyMustAnswer(t *testing.T) {
	invHome(t)
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()
	live, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	go func() {
		for {
			c, err := live.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	mustRun(t, "vpn", "add", "deadsocks", "socks", "--proxy-address", deadAddr)
	mustRun(t, "vpn", "add", "deadproxy", "proxy", "--proxy-address", deadAddr)
	mustRun(t, "vpn", "add", "livesocks", "socks", "--proxy-address", live.Addr().String())
	wantCode(t, "VPN_DOWN", "vpn", "up", "deadsocks")
	wantCode(t, "VPN_DOWN", "vpn", "up", "deadproxy")
	d, _ := invRun(t, "vpn", "test", "deadproxy")
	if r := d["results"].([]any)[0].(map[string]any); r["ok"] != false {
		t.Errorf("dead proxy tested ok: %v", r)
	}
	d = mustRun(t, "vpn", "test", "livesocks")
	if r := d["results"].([]any)[0].(map[string]any); r["ok"] != true {
		t.Errorf("live proxy: %v", r)
	}
}

// TestVpnDownSaysWhatStops: vpn down names the servers and conns that use
// the VPN, and whether they stop answering until a person's `vpn up` (a
// login with MFA) or connect it again on their next command.
func TestVpnDownSaysWhatStops(t *testing.T) {
	invHome(t)
	now := time.Now().UTC()
	if err := store.Update(store.Save, func(st *store.State) error {
		st.Vpns["client-x"] = &store.Vpn{Name: "client-x", Kind: "anyconnect", Portal: "vpn.example.test", MFA: true, CreatedAt: now, UpdatedAt: now}
		st.Vpns["office"] = &store.Vpn{Name: "office", Kind: "openvpn", Check: "10.0.0.1:22", CreatedAt: now, UpdatedAt: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "host", "add", "app", "u@10.0.0.5", "--via", "client-x")
	mustRun(t, "host", "add", "web", "u@10.0.0.6", "--via", "office")
	d := mustRun(t, "vpn", "down", "client-x", "office", "--dry-run")
	aff, _ := d["affects"].([]any)
	if len(aff) != 2 {
		t.Fatalf("dry run affects: %v", d)
	}
	if a := aff[0].(map[string]any); a["vpn"] != "client-x" || a["until"] != "vpn up" || a["next"] != "komando vpn up client-x" {
		t.Errorf("mfa vpn: %v", a)
	}
	if a := aff[1].(map[string]any); a["vpn"] != "office" || a["until"] != "next command" {
		t.Errorf("vpn without a person's login: %v", a)
	}
	// a running session (a stand-in process) is stopped, and down says so
	sleeper := sleeperCmd()
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() }()
	tcl.flags.dryRun = false // left on by the dry run above
	if err := store.UpdateRuntime(store.Save, func(st *store.State) error {
		st.Sessions["client-x"] = &store.VpnSession{Vpn: "client-x", PID: sleeper.Process.Pid, Exe: sleeperExe(), StartedAt: now, LastUsed: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if x := mustState(t).Sessions["client-x"]; x == nil || !netx.SessionAlive(x) {
		t.Fatalf("stand-in session: %+v", x)
	}
	d = mustRun(t, "vpn", "down", "client-x")
	if aff, _ := d["affects"].([]any); len(aff) != 1 {
		t.Fatalf("affects: %v", d)
	}
	txt := vpnDownData{Disconnected: []string{"client-x"}, Affects: vpnDownAffects(mustState(t), []string{"client-x"})}.Text()
	if !strings.Contains(txt, "app stop answering until a person runs `komando vpn up client-x`") {
		t.Errorf("text: %q", txt)
	}
}

func mustState(t *testing.T) *store.State {
	t.Helper()
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	return st
}
