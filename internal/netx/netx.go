// Package netx opens the networks komando reaches targets through
// (docs/features/vpn.md). WireGuard, SOCKS, HTTP proxies, L2TP, IPsec,
// IKEv2, Tailscale, OpenVPN and AnyConnect run inside komando, in user
// space, so the computer's routes are not changed. Only the openconnect
// family (globalprotect, fortinet, pulse, f5) uses an outside client when
// openconnect is installed; without it komando uses its own experimental
// client. A "system" VPN is one set up in the computer's own settings and
// does change routes.
// Session kinds run as a background session that later commands reuse.
package netx

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/sgnd/komando/internal/flock"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Dialer opens a TCP connection through a network.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Kind describes a VPN kind. Session kinds run a client in the background
// (`komando vpn up`), reused by later commands; Client names the program
// that must be installed for it.
type Kind struct {
	Desc     string
	Session  bool
	Client   []string
	Protocol string // openconnect --protocol
}

// Kinds are the VPN kinds komando knows.
var Kinds = map[string]Kind{
	"wireguard":     {Desc: "WireGuard, run inside komando (no admin rights, many at once)"},
	"socks":         {Desc: "a SOCKS5 proxy that is already running (`komando tunnel start TARGET -D`, a company proxy)"},
	"proxy":         {Desc: "an HTTP proxy (CONNECT), such as a company proxy: every connection is tunneled through it"},
	"system":        {Desc: "a VPN set up in your computer's settings; --service lets `vpn up` connect it"},
	"l2tp":          {Desc: "L2TP/IPsec with a pre-shared key, run inside komando (no admin rights)", Session: true},
	"ipsec":         {Desc: "Cisco-style IPsec (IKEv1, group name and XAUTH login), run inside komando", Session: true},
	"ikev2":         {Desc: "IKEv2/IPsec (pre-shared key or EAP login with a server certificate), run inside komando", Session: true},
	"tailscale":     {Desc: "Tailscale or Headscale, run inside komando (no tailscaled, no admin rights)", Session: true},
	"globalprotect": {Desc: "Palo Alto GlobalProtect", Session: true, Client: []string{"openconnect", "ocproxy"}, Protocol: "gp"},
	"fortinet":      {Desc: "Fortinet SSL VPN (FortiClient)", Session: true, Client: []string{"openconnect", "ocproxy"}, Protocol: "fortinet"},
	"anyconnect":    {Desc: "Cisco AnyConnect / ocserv, run inside komando (no openconnect)", Session: true},
	"pulse":         {Desc: "Pulse Secure / Ivanti Connect Secure", Session: true, Client: []string{"openconnect", "ocproxy"}, Protocol: "pulse"},
	"f5":            {Desc: "F5 BIG-IP SSL VPN", Session: true, Client: []string{"openconnect", "ocproxy"}, Protocol: "f5"},
	"openvpn":       {Desc: "OpenVPN, also Pritunl profiles, run inside komando (no openvpn program, Docker or admin rights)", Session: true},
}

// KindNames lists the kinds, sorted.
func KindNames() []string {
	n := make([]string, 0, len(Kinds))
	for k := range Kinds {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// StartSession is set by the CLI: it brings up a session for a VPN that can
// connect without a human (no MFA). Open calls it on demand.
var StartSession func(ctx context.Context, name string) error

// WriteFor is set by the CLI: how the runtime record (a session's last
// use, a dead session gone) changes for the command ctx belongs to:
// store.Preview under its --dry-run, so a preview writes nothing. Nil:
// store.Save.
var WriteFor func(ctx context.Context) store.Write

func writeFor(ctx context.Context) store.Write {
	if WriteFor == nil {
		return store.Save
	}
	return WriteFor(ctx)
}

// LoginRequired is the error for a VPN that needs a human to log in.
func LoginRequired(v *store.Vpn) error {
	return out.Errf(out.ExitConnect, "VPN_LOGIN_REQUIRED", "ask a person to run `komando vpn up "+v.Name+"` (it needs their login); then run it again",
		"VPN %s is not connected and needs a person to log in", v.Name)
}

// LiveSession returns the VPN's background session if it is running and
// not idle for longer than the vpn_idle setting. An idle one is stopped.
// It marks the session used, unless the command of ctx only previews
// (WriteFor).
func LiveSession(ctx context.Context, v *store.Vpn) *store.VpnSession {
	w := writeFor(ctx)
	st, err := store.Load()
	if err != nil {
		return nil
	}
	s := st.Sessions[v.Name]
	if s == nil {
		return nil
	}
	idle, _ := time.ParseDuration(st.Settings.VpnIdle)
	stale := func(x *store.VpnSession) bool {
		return !SessionAlive(x) || (idle > 0 && time.Since(x.LastUsed) > idle)
	}
	if stale(s) {
		stopIfStale(w, v.Name, s, stale)
		return nil
	}
	_ = store.UpdateRuntime(w, func(st *store.State) error {
		if x := st.Sessions[v.Name]; x != nil && sameSession(x, s) {
			x.LastUsed = time.Now().UTC()
		}
		return nil
	})
	return s
}

// SessionAlive reports whether a session's process runs.
func SessionAlive(s *store.VpnSession) bool {
	return Alive(s.PID) && isProgram(s.PID, s.Exe)
}

// isProgram checks that pid still runs the expected program: after a
// crash the pid may belong to something else, which must not be signalled.
func isProgram(pid int, exe string) bool {
	if exe == "" {
		return true
	}
	name, err := programName(pid)
	return err == nil && sameProgram(name, exe, runtime.GOOS == "windows")
}

// sameProgram reports whether name, the file name the system gives a
// running process, is the program exe. Linux shortens a process's name to
// 15 characters, so only that much of exe has to match; Windows file names
// do not care about case (fold).
func sameProgram(name, exe string, fold bool) bool {
	if len(exe) > 15 {
		exe = exe[:15]
	}
	if fold {
		name, exe = strings.ToLower(name), strings.ToLower(exe)
	}
	return name != "" && strings.HasPrefix(name, exe)
}

// ReapIdle closes sessions unused for longer than vpn_idle. It runs at
// the start of every komando command, so sessions do not stay up forever.
func ReapIdle() {
	st, err := store.Load()
	if err != nil || len(st.Sessions) == 0 {
		return
	}
	idle, err := time.ParseDuration(st.Settings.VpnIdle)
	if err != nil || idle <= 0 {
		return
	}
	stale := func(x *store.VpnSession) bool { return time.Since(x.LastUsed) > idle }
	for name, s := range st.Sessions {
		if stale(s) {
			stopIfStale(store.Save, name, s, stale)
		}
	}
}

// StopSession ends a session's process. A session that is no longer running is already stopped.
// It reports an error when it could not stop it; the caller keeps the
// session then.
func StopSession(s *store.VpnSession) error {
	if !SessionAlive(s) {
		return nil
	}
	return Terminate(s.PID)
}

func socksDialer(v *store.Vpn, s *store.VpnSession, timeout time.Duration) (Dialer, error) {
	var auth *proxy.Auth
	if s.SocksUser != "" {
		auth = &proxy.Auth{User: s.SocksUser, Password: s.SocksPass}
	}
	d, err := proxy.SOCKS5("tcp", s.Socks, auth, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, configErr(v, err)
	}
	cd := d.(proxy.ContextDialer)
	return func(ctx context.Context, network, a string) (net.Conn, error) {
		c, err := cd.DialContext(ctx, network, a)
		if err != nil {
			return nil, Down(v, err)
		}
		return c, nil
	}, nil
}

// sessionDialer dials through a running session and keeps the session's
// LastUsed fresh while the caller holds it (a long `logs --follow` must not
// look idle), until the closer is closed; w: Preview keeps it as it is.
func sessionDialer(w store.Write, v *store.Vpn, s *store.VpnSession, timeout time.Duration) (Dialer, io.Closer, error) {
	var d Dialer = (&net.Dialer{Timeout: timeout}).DialContext
	if s.Socks != "" {
		var err error
		if d, err = socksDialer(v, s, timeout); err != nil {
			return nil, nil, err
		}
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_ = store.UpdateRuntime(w, func(st *store.State) error {
					if x := st.Sessions[v.Name]; x != nil && sameSession(x, s) {
						x.LastUsed = time.Now().UTC()
					}
					return nil
				})
			}
		}
	}()
	return d, closerFunc(func() error { close(stop); return nil }), nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func sameSession(a, b *store.VpnSession) bool {
	return a.PID == b.PID && a.StartedAt.Equal(b.StartedAt)
}

// Lock holds the per-VPN lock that starting and stopping a session take,
// so a stale stop can never hit a session another process just started.
func Lock(name string) (unlock func(), err error) {
	if err := store.MkdirPrivate("vpn"); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(store.Path("vpn", name+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if ok, err := flock.TryLock(f); err != nil || !ok {
		// another komando holds it, maybe for minutes: a person may be
		// signing in there. Say so instead of standing still without a word
		if !ok && err == nil && LockBusy != nil {
			LockBusy(name)
		}
		if err := flock.Lock(f); err != nil {
			f.Close()
			return nil, err
		}
	}
	return func() { _ = flock.Unlock(f); f.Close() }, nil
}

// LockBusy, when set, is told that Lock has to wait for another komando
// that is starting or stopping the same VPN.
var LockBusy func(name string)

// stopIfStale stops and forgets a session under the VPN's lock, only if
// the stored entry is still the one that was found stale. With Preview the
// stopped session stays in the runtime record (the next command finds it
// dead and forgets it).
func stopIfStale(w store.Write, name string, s *store.VpnSession, stale func(*store.VpnSession) bool) {
	unlock, err := Lock(name)
	if err != nil {
		return
	}
	defer unlock()
	st, err := store.Load()
	if err != nil {
		return
	}
	cur := st.Sessions[name]
	if cur == nil || !sameSession(cur, s) || !stale(cur) {
		return
	}
	if StopSession(cur) == nil {
		_ = store.UpdateRuntime(w, func(st *store.State) error {
			if x := st.Sessions[name]; x != nil && sameSession(x, cur) {
				delete(st.Sessions, name)
			}
			return nil
		})
	}
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// Open starts v (or reuses its background session) and returns a dialer
// through it. Close the closer when done.
func Open(ctx context.Context, v *store.Vpn, timeout time.Duration) (Dialer, io.Closer, error) {
	if s := LiveSession(ctx, v); s != nil {
		return sessionDialer(writeFor(ctx), v, s, timeout)
	}
	if Kinds[v.Kind].Session {
		if v.MFA || StartSession == nil {
			return nil, nil, LoginRequired(v)
		}
		if err := StartSession(ctx, v.Name); err != nil {
			return nil, nil, err
		}
		s := LiveSession(ctx, v)
		if s == nil {
			return nil, nil, Down(v, fmt.Errorf("the session did not start"))
		}
		return sessionDialer(writeFor(ctx), v, s, timeout)
	}
	return OpenDirect(ctx, v, timeout)
}

// OpenDirect opens an in-process kind (wireguard, socks, system) without
// looking for a session. `komando vpn serve` uses it.
func OpenDirect(ctx context.Context, v *store.Vpn, timeout time.Duration) (Dialer, io.Closer, error) {
	switch v.Kind {
	case "wireguard":
		return openWireGuard(v)
	case "socks":
		var auth *proxy.Auth
		if v.User != "" {
			pw, err := secret(v, v.KeyRef)
			if err != nil {
				return nil, nil, err
			}
			auth = &proxy.Auth{User: v.User, Password: pw}
		}
		d, err := proxy.SOCKS5("tcp", v.Address, auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, nil, configErr(v, err)
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, nil, configErr(v, fmt.Errorf("SOCKS dialer without context support"))
		}
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := cd.DialContext(ctx, network, addr)
			if err != nil {
				return nil, Down(v, socksErr(v.Address, err))
			}
			return c, nil
		}, nopCloser{}, nil
	case "proxy":
		return openHTTPProxy(v, timeout)
	case "tailscale":
		return openTailscale(ctx, v, timeout)
	case "openvpn":
		return openOpenVPN(ctx, v, timeout)
	case "anyconnect", "fortinet", "globalprotect", "f5", "pulse":
		return openSSLVPN(ctx, v, timeout)
	case "l2tp", "ipsec", "ikev2":
		return openIPsec(ctx, v, timeout)
	case "system":
		if v.Check != "" { // connected by the OS, or by `vpn up` through --service
			c, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", v.Check)
			if err != nil {
				return nil, nil, Down(v, err)
			}
			c.Close()
		}
		return (&net.Dialer{Timeout: timeout}).DialContext, nopCloser{}, nil
	}
	return nil, nil, configErr(v, fmt.Errorf("komando has no VPN kind %q (a bug: report it)", v.Kind))
}

// socksErr says plainly when nothing runs at the proxy's address (the
// proxy library reports it as a failed dial inside a SOCKS error).
func socksErr(proxyAddr string, err error) error {
	if strings.Contains(err.Error(), "dial tcp "+proxyAddr+":") {
		return fmt.Errorf("the SOCKS proxy at %s is not running (nothing answers there)", proxyAddr)
	}
	return err
}

// Down is the error for a VPN that cannot be used right now. The hint
// says what to do for its kind.
func Down(v *store.Vpn, err error) error {
	return out.Errf(out.ExitConnect, "VPN_DOWN", DownHint(v), "VPN %s: %v", v.Name, err)
}

// DownHint is what to do when v does not answer.
func DownHint(v *store.Vpn) string {
	switch {
	case v.Kind == "system":
		return "connect the VPN " + v.Name + " on this computer first, then run it again"
	case v.Kind == "socks":
		return "start the SOCKS proxy at " + v.Address + ", for example `komando tunnel start TARGET -D " + v.Address + "`, then run it again"
	case v.Kind == "proxy":
		return "check that the proxy at " + v.Address + " answers and lets this port through (many company proxies allow only 443), and its login (`komando vpn show " + v.Name + "`)"
	case v.Kind == "wireguard":
		return "check that the endpoint is reachable from this computer and that the keys match the server's (`komando vpn show " + v.Name + "`)"
	case Kinds[v.Kind].Session:
		return "reconnect it with `komando vpn down " + v.Name + "` and `komando vpn up " + v.Name + "`"
	}
	return "check the VPN's settings with `komando vpn show " + v.Name + "`"
}

func configErr(v *store.Vpn, err error) error {
	return out.Errf(out.ExitUsage, "VPN_CONFIG", "fix it with `komando vpn add "+v.Name+" ... --overwrite`", "VPN %s: %v", v.Name, err)
}

func secret(v *store.Vpn, ref string) (string, error) {
	s, err := vault.Resolve(ref)
	if err != nil {
		return "", out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", SecretHint(ref), "VPN %s key %s: %v", v.Name, ref, err)
	}
	return s, nil
}

// SecretHint says how to provide a secret reference that does not resolve.
func SecretHint(ref string) string {
	switch {
	case strings.HasPrefix(ref, "secret:"):
		return "store it with `komando secret set " + strings.TrimPrefix(ref, "secret:") + "`"
	case strings.HasPrefix(ref, "env:"):
		return "set the environment variable " + strings.TrimPrefix(ref, "env:")
	case strings.HasPrefix(ref, "file:"):
		return "create the file " + strings.TrimPrefix(ref, "file:")
	}
	return "check that " + ref + " can be read on this computer (logged in to its secret manager?)"
}
