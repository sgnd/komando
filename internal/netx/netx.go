// Package netx opens the networks komando reaches targets through
// (docs/design/network.md). WireGuard and SOCKS run inside komando's own
// process, only for the connections that need them. Kinds that need an
// outside client (Tailscale, the openconnect family, OpenVPN) run as a
// background session that later commands reuse; most of them hand komando a
// local SOCKS port, so several VPNs work at once without touching the
// computer's routes. OpenVPN (OS mode) does change routes.
package netx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"

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
	"socks":         {Desc: "a SOCKS5 proxy that is already running (`komando tunnel start HOST -D`, a company proxy)"},
	"system":        {Desc: "a VPN set up in your computer's settings (L2TP/IPsec, IKEv2, ...); --service lets `vpn up` connect it"},
	"tailscale":     {Desc: "Tailscale or Headscale, through tailscaled in user-space mode", Session: true, Client: []string{"tailscaled", "tailscale"}},
	"globalprotect": {Desc: "Palo Alto GlobalProtect", Session: true, Client: []string{"openconnect", "ocproxy"}, Protocol: "gp"},
	"fortinet":      {Desc: "Fortinet SSL VPN (FortiClient)", Session: true, Client: []string{"openconnect", "ocproxy"}, Protocol: "fortinet"},
	"anyconnect":    {Desc: "Cisco AnyConnect / ocserv", Session: true, Client: []string{"openconnect", "ocproxy"}, Protocol: "anyconnect"},
	"pulse":         {Desc: "Pulse Secure / Ivanti Connect Secure", Session: true, Client: []string{"openconnect", "ocproxy"}, Protocol: "pulse"},
	"f5":            {Desc: "F5 BIG-IP SSL VPN", Session: true, Client: []string{"openconnect", "ocproxy"}, Protocol: "f5"},
	"openvpn":       {Desc: "OpenVPN, also Pritunl profiles (runs in a Docker container; --os-mode runs it on the computer with sudo)", Session: true, Client: []string{"docker"}},
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

// LoginRequired is the error for a VPN that needs a human to log in.
func LoginRequired(v *store.Vpn) error {
	return out.Errf(out.ExitConnect, "VPN_LOGIN_REQUIRED", "ask a human to run `komando vpn up "+v.Name+"` (it needs their login); then try again",
		"VPN %s is not connected and needs a person to log in", v.Name)
}

// LiveSession returns the VPN's background session if it is running and
// not idle for longer than the vpn_idle setting. An idle one is stopped.
func LiveSession(v *store.Vpn) *store.VpnSession {
	st, err := store.Load()
	if err != nil {
		return nil
	}
	s := st.Sessions[v.Name]
	if s == nil {
		return nil
	}
	idle, _ := time.ParseDuration(st.Settings.VpnIdle)
	if !SessionAlive(s) || (idle > 0 && time.Since(s.LastUsed) > idle) {
		StopSession(s)
		_ = store.Update(func(st *store.State) error { delete(st.Sessions, v.Name); return nil })
		return nil
	}
	_ = store.Update(func(st *store.State) error {
		if x := st.Sessions[v.Name]; x != nil {
			x.LastUsed = time.Now().UTC()
		}
		return nil
	})
	return s
}

// Alive reports whether a process exists.
func Alive(pid int) bool {
	if pid <= 1 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM) // EPERM: alive, owned by root
}

// Terminate asks one process to stop. It refuses every pid that is not a
// single other process: kill(-1) would signal every program of the user,
// kill(0) the whole process group, kill(1) init.
func Terminate(pid int) error {
	if pid <= 1 || pid == os.Getpid() {
		return fmt.Errorf("refusing to signal pid %d", pid)
	}
	return syscall.Kill(pid, syscall.SIGTERM)
}

// SessionAlive reports whether a session's process or container runs.
func SessionAlive(s *store.VpnSession) bool {
	if s.Container != "" {
		b, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", s.Container).Output()
		return err == nil && strings.TrimSpace(string(b)) == "true"
	}
	return Alive(s.PID)
}

// StopSession ends a session's process or container (through sudo for
// OS-mode ones).
func StopSession(s *store.VpnSession) {
	if s.Container != "" {
		_ = exec.Command("docker", "rm", "-f", s.Container).Run()
		return
	}
	if s.PID <= 1 {
		return
	}
	if s.Sudo {
		_ = exec.Command("sudo", "-n", "kill", strconv.Itoa(s.PID)).Run()
		return
	}
	_ = Terminate(s.PID)
}

func socksDialer(v *store.Vpn, addr string, timeout time.Duration) (Dialer, error) {
	d, err := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: timeout})
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

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// Open starts v (or reuses its background session) and returns a dialer
// through it. Close the closer when done.
func Open(ctx context.Context, v *store.Vpn, timeout time.Duration) (Dialer, io.Closer, error) {
	if s := LiveSession(v); s != nil {
		if s.Socks == "" { // OS mode: the computer routes it
			return (&net.Dialer{Timeout: timeout}).DialContext, nopCloser{}, nil
		}
		d, err := socksDialer(v, s.Socks, timeout)
		return d, nopCloser{}, err
	}
	if Kinds[v.Kind].Session {
		if v.MFA || StartSession == nil {
			return nil, nil, LoginRequired(v)
		}
		if err := StartSession(ctx, v.Name); err != nil {
			return nil, nil, err
		}
		s := LiveSession(v)
		if s == nil {
			return nil, nil, Down(v, fmt.Errorf("the session did not start"))
		}
		if s.Socks == "" {
			return (&net.Dialer{Timeout: timeout}).DialContext, nopCloser{}, nil
		}
		d, err := socksDialer(v, s.Socks, timeout)
		return d, nopCloser{}, err
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
				return nil, Down(v, err)
			}
			return c, nil
		}, nopCloser{}, nil
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
	return nil, nil, configErr(v, fmt.Errorf("unknown kind %q", v.Kind))
}

// Down is the error for a VPN that cannot be used right now.
func Down(v *store.Vpn, err error) error {
	hint := "check the VPN with `komando test " + v.Name + "`"
	if v.Kind == "system" {
		hint = "connect the VPN " + v.Name + " on this computer first, then try again"
	}
	return out.Errf(out.ExitConnect, "VPN_DOWN", hint, "VPN %s: %v", v.Name, err)
}

func configErr(v *store.Vpn, err error) error {
	return out.Errf(out.ExitUsage, "VPN_CONFIG", "fix it with `komando vpn add "+v.Name+" ... --overwrite`", "VPN %s: %v", v.Name, err)
}

func secret(v *store.Vpn, ref string) (string, error) {
	s, err := vault.Resolve(ref)
	if err != nil {
		return "", out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", "store it with `komando secret set NAME`", "VPN %s key %s: %v", v.Name, ref, err)
	}
	return s, nil
}
