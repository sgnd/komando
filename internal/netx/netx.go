// Package netx opens the networks komando reaches targets through
// (docs/design/network.md). A VPN runs inside komando's own process, only
// for the connections that need it, so several can be open at once and the
// computer's routes, DNS and firewall never change.
package netx

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/net/proxy"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Dialer opens a TCP connection through a network.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Kinds are the VPN kinds komando knows, with a line for help texts.
var Kinds = map[string]string{
	"wireguard": "WireGuard, run inside komando (no admin rights, many at once)",
	"socks":     "a SOCKS5 proxy that is already running (ssh -D, tailscale, a company proxy)",
	"system":    "a VPN your computer runs itself (OpenVPN, AnyConnect, ...); komando only checks it is up",
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// Open starts v and returns a dialer through it. Close the closer when done.
func Open(ctx context.Context, v *store.Vpn, timeout time.Duration) (Dialer, io.Closer, error) {
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
		if v.Check != "" {
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
