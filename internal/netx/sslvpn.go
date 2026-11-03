package netx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/sslvpn"
	"github.com/sgnd/komando/internal/store"
)

// Corporate SSL VPNs run inside komando (internal/sslvpn). A login that
// needs a person happens at the terminal (SSLVPNLogin); the session's
// server gets only the session cookie.

// builtinSSL are the SSL VPN kinds komando speaks itself. experimentalSSL
// are written but not yet tested against the vendor's own servers: they
// are used when openconnect is not installed (before, those VPNs could not
// work at all), or when KOMANDO_EXPERIMENTAL_VPN names them (or says all);
// with openconnect installed, it still carries them.
var builtinSSL = map[string]bool{"anyconnect": true}
var experimentalSSL = map[string]bool{"fortinet": true, "globalprotect": true, "f5": true, "pulse": true}

// BuiltinSSL reports whether komando speaks the kind itself.
func BuiltinSSL(kind string) bool {
	if builtinSSL[kind] {
		return true
	}
	if !experimentalSSL[kind] {
		return false
	}
	for _, k := range strings.Split(os.Getenv("KOMANDO_EXPERIMENTAL_VPN"), ",") {
		if k = strings.TrimSpace(k); k == kind || k == "all" {
			return true
		}
	}
	_, err := exec.LookPath("openconnect")
	return err != nil
}

func sslOptions(v *store.Vpn, password string, prompt func(string, bool) (string, error)) sslvpn.Options {
	return sslvpn.Options{Portal: v.Portal, User: v.User, Password: password, Prompt: prompt}
}

// SSLVPNLogin logs in at the terminal and returns the session cookie.
func SSLVPNLogin(ctx context.Context, v *store.Vpn, prompt func(label string, secret bool) (string, error)) (string, error) {
	password := ""
	if v.KeyRef != "" {
		var err error
		if password, err = secret(v, v.KeyRef); err != nil {
			return "", err
		}
	} else if prompt != nil {
		var err error
		if password, err = prompt("Password for "+v.User, true); err != nil {
			return "", err
		}
	}
	o := sslOptions(v, password, prompt)
	switch v.Kind {
	case "anyconnect":
		c, err := sslvpn.AnyConnectLogin(ctx, o)
		return c, sslErr(v, err)
	case "fortinet":
		c, err := sslvpn.FortinetLogin(ctx, o)
		return c, sslErr(v, err)
	case "globalprotect":
		s, err := sslvpn.GlobalProtectLogin(ctx, o)
		return s.String(), sslErr(v, err)
	case "f5":
		c, err := sslvpn.F5Login(ctx, o)
		return c, sslErr(v, err)
	case "pulse":
		c, err := sslvpn.PulseLogin(ctx, o)
		return c, sslErr(v, err)
	}
	return "", fmt.Errorf("%s is not built in", v.Kind)
}

func openSSLVPN(ctx context.Context, v *store.Vpn, timeout time.Duration) (Dialer, io.Closer, error) {
	cookie := SessionSecret
	ctx, cancel := context.WithTimeout(ctx, max(timeout, 60*time.Second))
	defer cancel()
	if cookie == "" { // no person: only a stored password can log in
		if v.MFA {
			return nil, nil, LoginRequired(v)
		}
		var err error
		if cookie, err = SSLVPNLogin(ctx, v, nil); err != nil {
			return nil, nil, err
		}
	}
	var t sslvpn.Tunnel
	var err error
	o := sslOptions(v, "", nil)
	switch v.Kind {
	case "anyconnect":
		t, err = sslvpn.AnyConnectTunnel(ctx, o, cookie)
	case "fortinet":
		t, err = sslvpn.FortinetTunnel(ctx, o, cookie)
	case "f5":
		t, err = sslvpn.F5Tunnel(ctx, o, cookie)
	case "pulse":
		t, err = sslvpn.PulseTunnel(ctx, o, cookie)
	case "globalprotect":
		var s sslvpn.GPSession
		if s, err = sslvpn.ParseGPSession(cookie); err == nil {
			t, err = sslvpn.GlobalProtectTunnel(ctx, o, s)
		}
	default:
		return nil, nil, configErr(v, fmt.Errorf("%s is not built in", v.Kind))
	}
	if err != nil {
		return nil, nil, sslErr(v, err)
	}
	return stackDialer(v, t, t.Addresses(), t.DNS(), t.MTU())
}

func sslErr(v *store.Vpn, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sslvpn.ErrNeedsPerson) {
		return LoginRequired(v)
	}
	return Down(v, err)
}
