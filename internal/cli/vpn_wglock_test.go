package cli

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/netx"
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
	st, _ := store.Load()
	_, err := wgSharedSession(testCall(), st.Vpns["office"])
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
	s, err := wgSharedSession(testCall(), st.Vpns["office-2"])
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
	liveSocks(t, pub, store.Home(), "office")
	st, _ := store.Load()
	if _, err := wgSharedSession(testCall(), st.Vpns["office-2"]); toErr(err).Code != "VPN_KEY_IN_USE" {
		t.Fatalf("err = %v; want VPN_KEY_IN_USE", err)
	}
}

// No holder: a new session starts.
func TestWGKeyFree(t *testing.T) {
	wgKeyHome(t, "office")
	st, _ := store.Load()
	if s, err := wgSharedSession(testCall(), st.Vpns["office"]); s != nil || err != nil {
		t.Fatalf("= %+v, %v; want nothing", s, err)
	}
}

func TestWGHealth(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	since := now.Add(-time.Hour)
	for _, c := range []struct {
		last   time.Time
		since  time.Time
		dead   bool
		age    int64
		detail string
	}{
		{now.Add(-40 * time.Second), since, false, 40, "last WireGuard handshake 40s ago"},
		{now.Add(-5 * time.Minute), since, true, 300, "last WireGuard handshake 5m ago: the tunnel looks dead"},
		{time.Time{}, now.Add(-time.Minute), false, 0, "session running, no WireGuard handshake yet"},
		{time.Time{}, since, true, 0, "no WireGuard handshake in the 1h since it started: the tunnel looks dead"},
	} {
		var r vpnStatusRow
		wgHealth(&r, c.last, c.since, now)
		if r.TunnelDead != c.dead || r.HandshakeAge != c.age || r.Detail != c.detail {
			t.Errorf("last %v: got dead=%v age=%d %q", c.last, r.TunnelDead, r.HandshakeAge, r.Detail)
		}
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
	if err := os.WriteFile(handshakeFile("office"), []byte(itoa64(now.Add(-4*time.Minute).Unix())), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := store.Load()
	var row vpnStatusRow
	for _, r := range vpnStatusRows(st) {
		if r.Name == "office" {
			row = r
		}
	}
	if !row.Up || !row.TunnelDead || row.HandshakeAge != 240 || row.LastHandshake.IsZero() {
		t.Fatalf("row = %+v", row)
	}
	if txt := (vpnStatusData{Vpns: []vpnStatusRow{row}}).Text(); !strings.Contains(txt, "last WireGuard handshake 4m ago: the tunnel looks dead") {
		t.Fatalf("text:\n%s", txt)
	}
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
