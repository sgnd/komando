package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
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
	if shared, err := wgSharedSession(cl, ctx, v); err != nil || shared != nil {
		return shared, err
	}
	pid, addr, err := spawnServe(ctx, v.Name, logFile, 15*time.Second, s)
	if err != nil {
		// The serve lost the key to another `vpn up`: reuse that session or
		// name it. Any other VPN_DOWN keeps its own log.
		if e := toErr(err); e.Code == "VPN_DOWN" && strings.Contains(e.Message, "ERROR VPN_KEY_IN_USE") {
			if shared, err2 := wgSharedSession(cl, ctx, v); err2 != nil || shared != nil {
				return shared, err2
			}
		}
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

// wgStartWait bounds how long `vpn up` waits for a session of this home
// that holds the key but is not READY yet; tests shorten it.
var wgStartWait = 5 * time.Second

// wgSharedSession checks the key lock before a new session starts. A
// session of this home that runs the key and answers is reused for v; one
// of this home that is still starting is waited for, up to wgStartWait or
// ctx; one that runs elsewhere, or does not answer, is VPN_KEY_IN_USE.
// The SOCKS login of a session never leaves the home that started it.
func wgSharedSession(cl *call, ctx context.Context, v *store.Vpn) (*store.VpnSession, error) {
	pub, err := wgPublicKeyOf(v)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wgStartWait)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		h, err := netx.KeyInUse(pub)
		if err != nil || h == nil {
			return nil, err
		}
		if s := reusableSession(h); s != nil {
			return shareSession(cl, v, s)
		}
		if !wgStarting(h) || time.Now().After(deadline) {
			return nil, vpnInUse(v, h)
		}
		select {
		case <-ctx.Done():
			return nil, toErr(ctx.Err())
		case <-tick.C:
		}
	}
}

// wgStarting reports whether holder h is a session of this home on its
// way up: no SOCKS address yet, or one that answers before `vpn up` has
// saved its session.
func wgStarting(h *netx.KeyHolder) bool {
	if filepath.Clean(h.Home) != filepath.Clean(store.Home()) {
		return false
	}
	return h.Socks == "" || listening(h.Socks)
}

// shareSession records session s, which runs v's key, as v's session too.
func shareSession(cl *call, v *store.Vpn, s *store.VpnSession) (*store.VpnSession, error) {
	shared := *s
	shared.Vpn, shared.SharedWith, shared.LastUsed = v.Name, s.Vpn, time.Now().UTC()
	if err := store.UpdateRuntime(cl.storeWrite(), func(st *store.State) error { st.Sessions[v.Name] = &shared; return nil }); err != nil {
		return nil, err
	}
	_ = netx.EditKeyUsers(s.PID, s.ProcStart, func(users []string) []string {
		return append(liveKeyUsers(users, s, v.Name), v.Name)
	})
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
type wgHold struct {
	h    netx.KeyHolder
	stop chan struct{} // ends the handshake writer
	log  io.Writer     // the session log, for a write that fails
}

// holdWGKey claims v's key for this process before the tunnel starts.
func holdWGKey(v *store.Vpn, log io.Writer) (*wgHold, error) {
	if v.Kind != "wireguard" {
		return nil, nil
	}
	pub, err := wgPublicKeyOf(v)
	if err != nil {
		return nil, err
	}
	pid := os.Getpid()
	w := &wgHold{h: netx.KeyHolder{PublicKey: pub, PID: pid, ProcStart: netx.ProcessStart(pid), Home: store.Home(), Vpn: v.Name}, stop: make(chan struct{}), log: log}
	other, err := netx.ClaimKey(w.h)
	if err != nil {
		return nil, err
	}
	if other != nil {
		return nil, vpnInUse(v, other)
	}
	return w, nil
}

// serving records the SOCKS address and starts writing the tunnel's
// health for `vpn status` until release.
func (w *wgHold) serving(addr string, tunnel io.Closer) {
	if w == nil {
		return
	}
	w.h.Socks = addr
	_, _ = netx.ClaimKey(w.h)
	dev, ok := tunnel.(interface{ Stats() (netx.WGStats, error) })
	if !ok {
		return
	}
	path := handshakeFile(w.h.Vpn)
	_ = os.Remove(path) // a file of an earlier session
	go func() {
		var hw wgHealthWriter
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			if st, err := dev.Stats(); err == nil {
				hw.write(path, st, w.log)
			}
			select {
			case <-w.stop:
				return
			case <-t.C:
			}
		}
	}()
}

// release ends the handshake writer and gives the key back when the
// session stops cleanly.
func (w *wgHold) release() {
	if w == nil {
		return
	}
	close(w.stop)
	_ = netx.ReleaseKey(w.h.PublicKey, w.h.PID)
	_ = os.Remove(handshakeFile(w.h.Vpn))
}

// wgHealthFile is what `vpn serve` writes for `vpn status`: the last
// handshake, the bytes sent since it, and the keepalive interval.
type wgHealthFile struct {
	HandshakeAt int64  `json:"handshake_at"` // Unix seconds; 0 before the first
	TxSince     uint64 `json:"tx_since_handshake"`
	Keepalive   int    `json:"keepalive_seconds,omitempty"`
}

// wgHealthWriter turns device stats into wgHealthFile writes: only on a
// change, by a temporary file and a rename, and a failure is logged once.
type wgHealthWriter struct {
	last         wgHealthFile
	txAt         uint64 // tx bytes when the last handshake was seen
	seen, logged bool
}

func (hw *wgHealthWriter) write(path string, st netx.WGStats, log io.Writer) {
	f := wgHealthFile{HandshakeAt: st.LastHandshake.Unix(), Keepalive: st.Keepalive}
	if st.LastHandshake.IsZero() {
		f.HandshakeAt = 0
	}
	if !hw.seen || f.HandshakeAt != hw.last.HandshakeAt {
		hw.txAt = st.TxBytes
	}
	if f.HandshakeAt == 0 {
		hw.txAt = 0 // before the first handshake every byte sent waits for one
	}
	f.TxSince = st.TxBytes - min(hw.txAt, st.TxBytes)
	if hw.seen && f == hw.last {
		return
	}
	b, _ := json.Marshal(f)
	tmp := path + ".tmp"
	err := os.WriteFile(tmp, b, 0o600)
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		if !hw.logged && log != nil {
			fmt.Fprintf(log, "%s cannot write the WireGuard health file: %v\n", time.Now().Format("2006/01/02 15:04:05"), err)
		}
		hw.logged = true
		return
	}
	hw.last, hw.seen = f, true
}

// handshakeFile holds a WireGuard session's wgHealthFile for `vpn status`.
func handshakeFile(vpn string) string { return store.Path("vpn", vpn+".handshake") }

// readHandshake is the wgHealthFile `vpn serve` wrote for vpn; ok is false
// when there is none.
func readHandshake(vpn string) (f wgHealthFile, ok bool) {
	b, err := os.ReadFile(handshakeFile(vpn))
	if err != nil || json.Unmarshal(b, &f) != nil {
		return wgHealthFile{}, false
	}
	return f, true
}

// wgHealth fills a running WireGuard session's tunnel fields of r at now.
// Past wgDeadAfter without a handshake the tunnel is dead only when it had
// to answer: something was sent since, or a keepalive keeps it busy.
// Otherwise nothing used it and it is idle: WireGuard does not handshake
// on an unused tunnel.
func wgHealth(r *vpnStatusRow, f wgHealthFile, since, now time.Time) {
	last := time.Time{}
	if f.HandshakeAt > 0 {
		last = time.Unix(f.HandshakeAt, 0).UTC()
	}
	r.LastHandshake = last
	quiet := now.Sub(since)
	if !last.IsZero() {
		quiet = max(now.Sub(last), 0)
		r.HandshakeAge = int64(quiet / time.Second)
	}
	r.TunnelState = "up"
	if quiet > wgDeadAfter {
		r.TunnelState = "idle"
		if f.TxSince > 0 || f.Keepalive > 0 {
			r.TunnelState, r.TunnelDead = "dead", true
		}
	}
	switch {
	case last.IsZero() && r.TunnelDead:
		r.Detail = fmt.Sprintf("no WireGuard handshake in the %s since it started: the tunnel looks dead", humanAge(quiet))
	case last.IsZero() && r.TunnelState == "idle":
		r.Detail = "idle: nothing used it since it started, so no WireGuard handshake yet"
	case last.IsZero():
		r.Detail = "session running, no WireGuard handshake yet"
	default:
		r.Detail = "last WireGuard handshake " + humanAge(quiet) + " ago"
		if r.TunnelDead {
			r.Detail += ": the tunnel looks dead"
		} else if r.TunnelState == "idle" {
			r.Detail += ": idle, nothing sent since"
		}
	}
}

// liveKeyUsers is users without skip and without the entries whose
// session record is gone or is not process s any more (a crash, a stop).
func liveKeyUsers(users []string, s *store.VpnSession, skip string) []string {
	st, err := store.Load()
	if err != nil {
		return users
	}
	var live []string
	for _, n := range users {
		x := st.Sessions[n]
		if n != skip && x != nil && x.PID == s.PID && x.ProcStart == s.ProcStart && !slices.Contains(live, n) {
			live = append(live, n)
		}
	}
	return live
}

// sessionKeptFor names the other VPNs that use the session process of VPN
// name (one WireGuard key, shared_with) and are not in stopping: `vpn
// down` removes only name's entry and the process keeps running for them.
// The last user's `vpn down` stops it.
func sessionKeptFor(st *store.State, name string, stopping []string) []string {
	s := st.Sessions[name]
	if s == nil {
		return nil
	}
	var keep []string
	for n, x := range st.Sessions {
		if n != name && !slices.Contains(stopping, n) && x.PID == s.PID && x.ProcStart == s.ProcStart && netx.SessionAlive(x) {
			keep = append(keep, n)
		}
	}
	sort.Strings(keep)
	return keep
}

// leaveSharedSession drops VPN name from its session's users when others
// still use it; false when name is the last user and the session stops.
func leaveSharedSession(st *store.State, name string, stopping []string) (kept []string) {
	keep := sessionKeptFor(st, name, stopping)
	if len(keep) == 0 {
		return nil
	}
	s := st.Sessions[name]
	_ = netx.EditKeyUsers(s.PID, s.ProcStart, func([]string) []string { return keep })
	return keep
}

func keptNote(name string, keep []string) string {
	return name + ": the session stays up for " + strings.Join(keep, ", ") + " (the same WireGuard key)"
}

// keptNotes says for each VPN in names with a session whether `vpn down`
// leaves the session up for others or stops it.
func keptNotes(st *store.State, names []string) []string {
	var notes []string
	for _, n := range names {
		s := st.Sessions[n]
		if s == nil {
			continue
		}
		if keep := sessionKeptFor(st, n, names); len(keep) > 0 {
			notes = append(notes, keptNote(n, keep))
		} else if s.SharedWith != "" || len(sessionKeptFor(st, n, nil)) > 0 {
			notes = append(notes, n+": stops the session")
		}
	}
	return notes
}
