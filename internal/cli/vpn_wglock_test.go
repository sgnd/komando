package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// wgKeyHome is a temp home with WireGuard VPN name whose key comes from an
// environment variable, and a temp key lock folder; it returns the key's
// public half.
func wgKeyHome(t *testing.T, name string) string {
	t.Helper()
	setHome(t, t.TempDir())
	dir := t.TempDir()
	old := netx.KeyLockDir
	netx.KeyLockDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { netx.KeyLockDir = old })
	oldWait := wgStartWait
	wgStartWait = 300 * time.Millisecond
	t.Cleanup(func() { wgStartWait = oldWait })
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_TEST_WG_KEY", base64.StdEncoding.EncodeToString(k))
	now := time.Now().UTC()
	if err := store.Update(store.Save(), func(st *store.State) error {
		for _, n := range []string{name, name + "-2"} {
			st.Vpns[n] = &store.Vpn{Name: n, Kind: "wireguard", KeyRef: "env:KOMANDO_TEST_WG_KEY", CreatedAt: now, UpdatedAt: now}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pub, err := wgPublicKeyOf(&store.Vpn{Name: name, KeyRef: "env:KOMANDO_TEST_WG_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// liveSocks is a listening SOCKS stand-in and a holder record for this
// test process, as a running `vpn serve` would leave it.
func liveSocks(t *testing.T, pub, home, vpn string) netx.KeyHolder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	h := netx.KeyHolder{PublicKey: pub, PID: os.Getpid(), ProcStart: netx.ProcessStart(os.Getpid()), Socks: ln.Addr().String(), Home: home, Vpn: vpn}
	if other, err := netx.ClaimKey(h); err != nil || other != nil {
		t.Fatalf("claim: %+v, %v", other, err)
	}
	return h
}

// The same key from another home is refused with VPN_KEY_IN_USE, naming the
// process and its home.
func TestWGKeyOtherHomeRefused(t *testing.T) {
	pub := wgKeyHome(t, "office")
	liveSocks(t, pub, "/elsewhere/.komando", "corp")
	wgStartWait = 5 * time.Second
	st, _ := store.Load()
	start := time.Now()
	_, err := wgSharedSession(testCall(), context.Background(), st.Vpns["office"])
	if d := time.Since(start); d > time.Second {
		t.Fatalf("waited %v for a session of another home", d)
	}
	e := toErr(err)
	if e == nil || e.Code != "VPN_KEY_IN_USE" || e.Exit != 8 {
		t.Fatalf("err = %v; want VPN_KEY_IN_USE exit 8", err)
	}
	if !strings.Contains(e.Message, "/elsewhere/.komando") || !strings.Contains(e.Message, "corp") {
		t.Fatalf("message does not name the other session: %s", e.Message)
	}
	if !strings.Contains(e.Hint, "KOMANDO_HOME=/elsewhere/.komando komando vpn down corp") {
		t.Fatalf("hint: %s", e.Hint)
	}
}

// The same key in this home, with its session answering, is reused.
func TestWGKeySameHomeReused(t *testing.T) {
	pub := wgKeyHome(t, "office")
	h := liveSocks(t, pub, store.Home(), "office")
	now := time.Now().UTC()
	if err := store.UpdateRuntime(store.Save(), func(st *store.State) error {
		st.Sessions["office"] = &store.VpnSession{Vpn: "office", PID: h.PID, ProcStart: h.ProcStart, Socks: h.Socks, SocksUser: "u", SocksPass: "p", StartedAt: now, LastUsed: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, _ := store.Load()
	s, err := wgSharedSession(testCall(), context.Background(), st.Vpns["office-2"])
	if err != nil || s == nil || s.Socks != h.Socks || s.SharedWith != "office" || s.Vpn != "office-2" {
		t.Fatalf("shared = %+v, %v", s, err)
	}
	st, _ = store.Load()
	if x := st.Sessions["office-2"]; x == nil || x.PID != h.PID {
		t.Fatalf("session not recorded: %+v", x)
	}
}

// In this home but with no session that answers: refused, not reused.
func TestWGKeySameHomeDeadSocks(t *testing.T) {
	pub := wgKeyHome(t, "office")
	h := liveSocks(t, pub, store.Home(), "office")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.Socks = ln.Addr().String()
	ln.Close()
	if _, err := netx.ClaimKey(h); err != nil {
		t.Fatal(err)
	}
	wgStartWait = 5 * time.Second
	st, _ := store.Load()
	start := time.Now()
	if _, err := wgSharedSession(testCall(), context.Background(), st.Vpns["office-2"]); toErr(err).Code != "VPN_KEY_IN_USE" {
		t.Fatalf("err = %v; want VPN_KEY_IN_USE", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("waited %v for a session whose SOCKS port is closed", d)
	}
}

// A session of this home that holds the key but is not READY yet (no
// SOCKS address, no session record) is waited for and then reused.
func TestWGKeySameHomeStartingReused(t *testing.T) {
	pub := wgKeyHome(t, "office")
	wgStartWait = 5 * time.Second
	h := liveSocks(t, pub, store.Home(), "office")
	socks := h.Socks
	h.Socks = ""
	if _, err := netx.ClaimKey(h); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		h.Socks = socks
		_, _ = netx.ClaimKey(h)
		now := time.Now().UTC()
		_ = store.UpdateRuntime(store.Save(), func(st *store.State) error {
			st.Sessions["office"] = &store.VpnSession{Vpn: "office", PID: h.PID, ProcStart: h.ProcStart, Socks: socks, StartedAt: now, LastUsed: now}
			return nil
		})
	}()
	st, _ := store.Load()
	s, err := wgSharedSession(testCall(), context.Background(), st.Vpns["office-2"])
	if err != nil || s == nil || s.Socks != socks || s.SharedWith != "office" {
		t.Fatalf("shared = %+v, %v", s, err)
	}
}

// A starting session that never becomes READY is VPN_KEY_IN_USE after the wait.
func TestWGKeySameHomeStartingTimesOut(t *testing.T) {
	pub := wgKeyHome(t, "office")
	h := netx.KeyHolder{PublicKey: pub, PID: os.Getpid(), ProcStart: netx.ProcessStart(os.Getpid()), Home: store.Home(), Vpn: "office"}
	if _, err := netx.ClaimKey(h); err != nil {
		t.Fatal(err)
	}
	st, _ := store.Load()
	start := time.Now()
	_, err := wgSharedSession(testCall(), context.Background(), st.Vpns["office-2"])
	if toErr(err).Code != "VPN_KEY_IN_USE" || time.Since(start) < wgStartWait {
		t.Fatalf("err = %v after %v; want VPN_KEY_IN_USE after the wait", err, time.Since(start))
	}
}

// A `vpn serve` that lost the key to another `vpn up` (VPN_DOWN) leads to
// reuse of the winner's session, not VPN_DOWN.
func TestStartWGSessionLostClaimReuses(t *testing.T) {
	pub := wgKeyHome(t, "office")
	var h netx.KeyHolder
	old := spawnServe
	spawnServe = func(context.Context, string, string, time.Duration, *store.VpnSession) (int, string, error) {
		h = liveSocks(t, pub, store.Home(), "office")
		now := time.Now().UTC()
		_ = store.UpdateRuntime(store.Save(), func(st *store.State) error {
			st.Sessions["office"] = &store.VpnSession{Vpn: "office", PID: h.PID, ProcStart: h.ProcStart, Socks: h.Socks, StartedAt: now, LastUsed: now}
			return nil
		})
		return 0, "", out.Errf(out.ExitConnect, "VPN_DOWN", "", "VPN office-2 did not start: ERROR VPN_KEY_IN_USE: VPN office-2: its WireGuard key is in use")
	}
	t.Cleanup(func() { spawnServe = old })
	st, _ := store.Load()
	s, err := startWGSession(testCall(), context.Background(), st.Vpns["office-2"], filepath.Join(t.TempDir(), "log"), &store.VpnSession{Vpn: "office-2"})
	if err != nil || s == nil || s.Socks != h.Socks || s.SharedWith != "office" {
		t.Fatalf("= %+v, %v; want the session of office reused", s, err)
	}
}

// Ctrl-C while waiting for a starting session returns at once.
func TestWGSharedSessionCancelled(t *testing.T) {
	pub := wgKeyHome(t, "office")
	wgStartWait = 5 * time.Second
	h := netx.KeyHolder{PublicKey: pub, PID: os.Getpid(), ProcStart: netx.ProcessStart(os.Getpid()), Home: store.Home(), Vpn: "office"}
	if _, err := netx.ClaimKey(h); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	st, _ := store.Load()
	start := time.Now()
	_, err := wgSharedSession(testCall(), ctx, st.Vpns["office-2"])
	if err == nil || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("err = %v after %v; want the cancel at once", err, time.Since(start))
	}
}

// A `vpn serve` that failed for another reason keeps its VPN_DOWN: no
// wait on a holder that is komando's own dying child.
func TestStartWGSessionDownNotRetried(t *testing.T) {
	pub := wgKeyHome(t, "office")
	wgStartWait = 5 * time.Second
	old := spawnServe
	spawnServe = func(context.Context, string, string, time.Duration, *store.VpnSession) (int, string, error) {
		h := netx.KeyHolder{PublicKey: pub, PID: os.Getpid(), ProcStart: netx.ProcessStart(os.Getpid()), Home: store.Home(), Vpn: "office-2"}
		_, _ = netx.ClaimKey(h)
		return 0, "", out.Errf(out.ExitConnect, "VPN_DOWN", "", "VPN office-2 did not start: ERROR dial udp: no route to host")
	}
	t.Cleanup(func() { spawnServe = old })
	st, _ := store.Load()
	start := time.Now()
	_, err := startWGSession(testCall(), context.Background(), st.Vpns["office-2"], filepath.Join(t.TempDir(), "log"), &store.VpnSession{Vpn: "office-2"})
	if e := toErr(err); e == nil || e.Code != "VPN_DOWN" || !strings.Contains(e.Message, "no route") || time.Since(start) > time.Second {
		t.Fatalf("err = %v after %v; want the original VPN_DOWN at once", err, time.Since(start))
	}
}

// No holder: a new session starts.
func TestWGKeyFree(t *testing.T) {
	wgKeyHome(t, "office")
	st, _ := store.Load()
	if s, err := wgSharedSession(testCall(), context.Background(), st.Vpns["office"]); s != nil || err != nil {
		t.Fatalf("= %+v, %v; want nothing", s, err)
	}
}

func TestWGHealth(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	since := now.Add(-time.Hour)
	at := func(d time.Duration) int64 { return now.Add(-d).Unix() }
	for _, c := range []struct {
		f      wgHealthFile
		since  time.Time
		state  string
		age    int64
		detail string
	}{
		{wgHealthFile{HandshakeAt: at(40 * time.Second), TxSince: 99}, since, "up", 40, "last WireGuard handshake 40s ago"},
		{wgHealthFile{HandshakeAt: at(5 * time.Minute), TxSince: 120}, since, "dead", 300, "last WireGuard handshake 5m ago: the tunnel looks dead"},
		{wgHealthFile{HandshakeAt: at(5 * time.Minute), Keepalive: 25}, since, "dead", 300, "last WireGuard handshake 5m ago: the tunnel looks dead"},
		{wgHealthFile{HandshakeAt: at(5 * time.Minute)}, since, "idle", 300, "last WireGuard handshake 5m ago: idle, nothing sent since"},
		{wgHealthFile{}, now.Add(-time.Minute), "up", 0, "session running, no WireGuard handshake yet"},
		{wgHealthFile{TxSince: 300}, since, "dead", 0, "no WireGuard handshake in the 1h since it started: the tunnel looks dead"},
		{wgHealthFile{}, since, "idle", 0, "idle: nothing used it since it started, so no WireGuard handshake yet"},
	} {
		var r vpnStatusRow
		wgHealth(&r, c.f, c.since, now)
		if r.TunnelState != c.state || r.TunnelDead != (c.state == "dead") || r.HandshakeAge != c.age || r.Detail != c.detail {
			t.Errorf("%+v: got %s dead=%v age=%d %q", c.f, r.TunnelState, r.TunnelDead, r.HandshakeAge, r.Detail)
		}
	}
}

// The writer counts bytes sent since the last handshake, writes only on a
// change, and leaves no temporary file.
func TestWGHealthWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "office.handshake")
	var hw wgHealthWriter
	var log strings.Builder
	h1 := time.Unix(1700000000, 0)
	hw.write(path, netx.WGStats{LastHandshake: h1, TxBytes: 1000, Keepalive: 25}, &log)
	hw.write(path, netx.WGStats{LastHandshake: h1, TxBytes: 1300, Keepalive: 25}, &log)
	var f wgHealthFile
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &f); err != nil || f.HandshakeAt != h1.Unix() || f.TxSince != 300 || f.Keepalive != 25 {
		t.Fatalf("file = %s (%v)", b, err)
	}
	hw.write(path, netx.WGStats{LastHandshake: h1.Add(2 * time.Minute), TxBytes: 1400}, &log)
	b, _ = os.ReadFile(path)
	if json.Unmarshal(b, &f); f.TxSince != 0 {
		t.Fatalf("after a new handshake: %s", b)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary file left")
	}
	bad := filepath.Join(t.TempDir(), "missing", "x.handshake")
	var hw2 wgHealthWriter
	hw2.write(bad, netx.WGStats{TxBytes: 1}, &log)
	hw2.write(bad, netx.WGStats{TxBytes: 2}, &log)
	if n := strings.Count(log.String(), "cannot write"); n != 1 {
		t.Fatalf("logged %d times: %s", n, log.String())
	}
}

// vpn down on one of two VPNs sharing a session removes only its entry
// and leaves the process running for the other; the last one's stops it.
// The dry run says which.
func TestVpnDownSharedSession(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sleep(1) as the session process")
	}
	wgKeyHome(t, "office")
	proc := exec.Command("sleep", "60")
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Process.Kill(); _ = proc.Wait() })
	now := time.Now().UTC()
	pid := proc.Process.Pid
	start, err := netx.RecordStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateRuntime(store.Save(), func(st *store.State) error {
		st.Sessions["office"] = &store.VpnSession{Vpn: "office", PID: pid, ProcStart: start, Socks: "127.0.0.1:1", StartedAt: now, LastUsed: now}
		st.Sessions["office-2"] = &store.VpnSession{Vpn: "office-2", PID: pid, ProcStart: start, Socks: "127.0.0.1:1", SharedWith: "office", StartedAt: now, LastUsed: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		tcl.flags.dryRun, tcl.flags.yes = false, false
		root := newRoot(tcl)
		t.Cleanup(endCommand)
		root.SetArgs(append([]string{"-o", "json"}, args...))
		var buf bytes.Buffer
		saved := tcl.out.W
		tcl.out.W = &buf
		err := root.Execute()
		tcl.out.W = saved
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return buf.String()
	}
	if o := run("vpn", "down", "office-2", "--dry-run"); !strings.Contains(o, "office-2: the session stays up for office (the same WireGuard key)") {
		t.Fatalf("dry run: %s", o)
	}
	if o := run("vpn", "down", "office-2"); !strings.Contains(o, "office-2: the session stays up for office (the same WireGuard key)") {
		t.Fatalf("down: %s", o)
	}
	st, _ := store.Load()
	if st.Sessions["office-2"] != nil || st.Sessions["office"] == nil || !netx.SessionAlive(st.Sessions["office"]) {
		t.Fatalf("after B down: %v", st.Sessions)
	}
	st.Sessions["office-2"] = st.Sessions["office"] // only to ask the dry run with a sharer present
	if n := keptNotes(st, []string{"office", "office-2"}); len(n) != 2 || !strings.Contains(n[0], "stops the session") {
		t.Fatalf("both down: %v", n)
	}
	run("vpn", "down", "office")
	if !waitFor(5*time.Second, func() bool { return !netx.Alive(pid) || proc.ProcessState != nil || netx.ProcessStart(pid) != start }) {
		_ = proc.Wait()
	}
	st, _ = store.Load()
	if st.Sessions["office"] != nil {
		t.Fatalf("A's record left: %v", st.Sessions)
	}
}

// A user whose session record is gone (a crash) is dropped from the key
// lock's users the next time a VPN joins the session.
func TestWGKeyUsersPruned(t *testing.T) {
	pub := wgKeyHome(t, "office")
	h := liveSocks(t, pub, store.Home(), "office")
	h.Users = []string{"office", "crashed"}
	if _, err := netx.ClaimKey(h); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.UpdateRuntime(store.Save(), func(st *store.State) error {
		st.Sessions["office"] = &store.VpnSession{Vpn: "office", PID: h.PID, ProcStart: h.ProcStart, Socks: h.Socks, StartedAt: now, LastUsed: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, _ := store.Load()
	if _, err := wgSharedSession(testCall(), context.Background(), st.Vpns["office-2"]); err != nil {
		t.Fatal(err)
	}
	got, _ := netx.KeyInUse(pub)
	if got == nil || strings.Join(got.Users, ",") != "office,office-2" {
		t.Fatalf("users = %+v", got)
	}
}

// vpn status reads the handshake time `vpn serve` wrote, in text and JSON.
func TestVpnStatusHandshake(t *testing.T) {
	wgKeyHome(t, "office")
	now := time.Now().UTC()
	old := vpnNow
	vpnNow = func() time.Time { return now }
	t.Cleanup(func() { vpnNow = old })
	if err := store.UpdateRuntime(store.Save(), func(st *store.State) error {
		st.Sessions["office"] = &store.VpnSession{Vpn: "office", PID: os.Getpid(), ProcStart: netx.ProcessStart(os.Getpid()), Socks: "127.0.0.1:1", StartedAt: now.Add(-time.Hour), LastUsed: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MkdirPrivate("vpn"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(handshakeFile("office"), []byte(`{"handshake_at":`+itoa64(now.Add(-4*time.Minute).Unix())+`,"tx_since_handshake":52}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := store.Load()
	var row vpnStatusRow
	for _, r := range vpnStatusRows(st) {
		if r.Name == "office" {
			row = r
		}
	}
	if !row.Up || !row.TunnelDead || row.TunnelState != "dead" || row.HandshakeAge != 240 || row.LastHandshake.IsZero() {
		t.Fatalf("row = %+v", row)
	}
	if txt := (vpnStatusData{Vpns: []vpnStatusRow{row}}).Text(); !strings.Contains(txt, "last WireGuard handshake 4m ago: the tunnel looks dead") {
		t.Fatalf("text:\n%s", txt)
	}
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
