package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// wgDeadAfter is how old the last handshake may be before `vpn status`
// says the tunnel looks dead: WireGuard renews a session key every two
// minutes of use and gives up on it after three (REJECT_AFTER_TIME).
const wgDeadAfter = 3 * time.Minute

// wgPublicKeyOf is the public key of WireGuard VPN v's interface key.
func wgPublicKeyOf(v *store.Vpn) (string, error) {
	priv, err := vault.Resolve(v.KeyRef)
	if err != nil {
		return "", out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", netx.SecretHint(v.KeyRef), "VPN %s private key %s: %v", v.Name, v.KeyRef, err)
	}
	return netx.WGPublicKey(priv)
}

// vpnInUse is the error (VPN_KEY_IN_USE) for a WireGuard key another live session holds.
func vpnInUse(v *store.Vpn, h *netx.KeyHolder) error {
	down := "komando vpn down " + h.Vpn
	if filepath.Clean(h.Home) != filepath.Clean(store.Home()) {
		down = "KOMANDO_HOME=" + h.Home + " " + down
	}
	return out.Errf(out.ExitConflict, "VPN_KEY_IN_USE",
		"one WireGuard key runs in one session at a time: stop the other with `"+down+"`, or give this VPN a key of its own with `komando vpn add "+v.Name+" wireguard --config FILE`",
		"VPN %s: its WireGuard key is in use by komando process %d (VPN %s, komando home %s)", v.Name, h.PID, h.Vpn, h.Home)
}

// startWGSession starts the `vpn serve` process of WireGuard VPN v, or
// reuses the session that already runs its key in this home.
func startWGSession(cl *call, ctx context.Context, v *store.Vpn, logFile string, s *store.VpnSession) (*store.VpnSession, error) {
	if shared, err := wgSharedSession(cl, v); err != nil || shared != nil {
		return shared, err
	}
	pid, addr, err := spawnServe(ctx, v.Name, logFile, 15*time.Second, s)
	if err != nil {
		return nil, err
	}
	s.PID, s.Socks = pid, addr
	if self, err := os.Executable(); err == nil {
		s.Exe = filepath.Base(self)
	}
	if err := saveSession(cl, v, s); err != nil {
		return nil, err
	}
	return s, nil
}

// wgSharedSession checks the key lock before a new session starts. A
// session of this home that runs the key and answers is reused for v; one
// that runs elsewhere, or does not answer, is VPN_KEY_IN_USE. The SOCKS login
// of a session never leaves the home that started it.
func wgSharedSession(cl *call, v *store.Vpn) (*store.VpnSession, error) {
	pub, err := wgPublicKeyOf(v)
	if err != nil {
		return nil, err
	}
	h, err := netx.KeyInUse(pub)
	if err != nil || h == nil {
		return nil, err
	}
	s := reusableSession(h)
	if s == nil {
		return nil, vpnInUse(v, h)
	}
	shared := *s
	shared.Vpn, shared.SharedWith, shared.LastUsed = v.Name, s.Vpn, time.Now().UTC()
	if err := store.UpdateRuntime(cl.storeWrite(), func(st *store.State) error { st.Sessions[v.Name] = &shared; return nil }); err != nil {
		return nil, err
	}
	noticef(cl, "vpn %s uses the running session of vpn %s (%s): both have the same WireGuard key", v.Name, s.Vpn, s.Socks)
	return &shared, nil
}

// reusableSession is this home's live session that h records, when its
// SOCKS port answers.
func reusableSession(h *netx.KeyHolder) *store.VpnSession {
	if filepath.Clean(h.Home) != filepath.Clean(store.Home()) || h.Socks == "" {
		return nil
	}
	st, err := store.Load()
	if err != nil {
		return nil
	}
	for _, s := range st.Sessions {
		if s.PID == h.PID && s.ProcStart == h.ProcStart && s.Socks == h.Socks && netx.SessionAlive(s) && listening(s.Socks) {
			return s
		}
	}
	return nil
}

// wgHold is a `vpn serve` process's claim on its WireGuard key; nil for
// other kinds, and every method takes nil.
type wgHold struct{ h netx.KeyHolder }

// holdWGKey claims v's key for this process before the tunnel starts.
func holdWGKey(v *store.Vpn) (*wgHold, error) {
	if v.Kind != "wireguard" {
		return nil, nil
	}
	pub, err := wgPublicKeyOf(v)
	if err != nil {
		return nil, err
	}
	pid := os.Getpid()
	w := &wgHold{netx.KeyHolder{PublicKey: pub, PID: pid, ProcStart: netx.ProcessStart(pid), Home: store.Home(), Vpn: v.Name}}
	other, err := netx.ClaimKey(w.h)
	if err != nil {
		return nil, err
	}
	if other != nil {
		return nil, vpnInUse(v, other)
	}
	return w, nil
}

// serving records the SOCKS address and starts writing handshake times.
func (w *wgHold) serving(addr string, tunnel io.Closer) {
	if w == nil {
		return
	}
	w.h.Socks = addr
	_, _ = netx.ClaimKey(w.h)
	hs, ok := tunnel.(interface{ LastHandshake() time.Time })
	if !ok {
		return
	}
	path := handshakeFile(w.h.Vpn)
	_ = os.Remove(path) // a file of an earlier session
	go func() {
		var last time.Time
		for {
			if t := hs.LastHandshake(); !t.IsZero() && !t.Equal(last) {
				last = t
				_ = os.WriteFile(path, []byte(strconv.FormatInt(t.Unix(), 10)), 0o600)
			}
			time.Sleep(10 * time.Second)
		}
	}()
}

// release gives the key back when the session stops cleanly.
func (w *wgHold) release() {
	if w == nil {
		return
	}
	_ = netx.ReleaseKey(w.h.PublicKey, w.h.PID)
	_ = os.Remove(handshakeFile(w.h.Vpn))
}

// handshakeFile holds the time of a WireGuard session's last handshake,
// in Unix seconds, for `vpn status`.
func handshakeFile(vpn string) string { return store.Path("vpn", vpn+".handshake") }

// readHandshake is the last handshake `vpn serve` wrote for vpn; zero when
// there is none yet.
func readHandshake(vpn string) time.Time {
	b, err := os.ReadFile(handshakeFile(vpn))
	if err != nil {
		return time.Time{}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

// wgHealth fills a running WireGuard session's handshake fields of r at now.
func wgHealth(r *vpnStatusRow, last, since, now time.Time) {
	r.LastHandshake = last
	switch {
	case last.IsZero() && now.Sub(since) > wgDeadAfter:
		r.TunnelDead = true
		r.Detail = fmt.Sprintf("no WireGuard handshake in the %s since it started: the tunnel looks dead", humanAge(now.Sub(since)))
	case last.IsZero():
		r.Detail = "session running, no WireGuard handshake yet"
	default:
		age := max(now.Sub(last), 0)
		r.HandshakeAge = int64(age / time.Second)
		r.Detail = "last WireGuard handshake " + humanAge(age) + " ago"
		if age > wgDeadAfter {
			r.TunnelDead = true
			r.Detail += ": the tunnel looks dead"
		}
	}
}
