package sshx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
	"github.com/sgnd/komando/internal/winrm"
)

// dialWinRM reaches a Windows server over WinRM: directly, through the VPN
// its --via starts with, or through its --via SSH servers (the HTTPS
// connection is carried by the last one, like a tunnel). Nothing is sent
// until the first command; the login happens then.
func dialWinRM(ctx context.Context, st *store.State, h *store.Host, o Options) (*Client, error) {
	if !o.WinRM || o.scan != nil {
		return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"WinRM carries PowerShell commands only: use `komando exec "+h.Name+" -- ...`; for a shell, tunnels or SSH host keys, turn on OpenSSH on the server and add it with --os windows (docs/features/windows.md)",
			"%s is reached over WinRM, which cannot do this (it has no SSH)", h.Name)
	}
	pass, err := winrmPassword(h)
	if err != nil {
		return nil, err
	}
	tc, err := winrmTLS(h)
	if err != nil {
		return nil, err
	}
	vpn, hops, err := resolveChain(st, h, map[string]bool{})
	if err != nil {
		return nil, err
	}
	cl := &Client{Host: h}
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	if jumps := hops[:len(hops)-1]; len(jumps) > 0 {
		sc, err := openJumps(ctx, st, vpn, jumps, o)
		if err != nil {
			return nil, err
		}
		cl.chain = sc
		dial = func(_ context.Context, network, addr string) (net.Conn, error) { return sc.last().Dial(network, addr) }
	} else {
		first, vpnCloser, err := openFirst(ctx, vpn, o)
		if err != nil {
			return nil, err
		}
		cl.vpn, dial = vpnCloser, first
	}
	opts := winrmOpts(h)
	scheme := "https"
	if opts.TLS == "off" {
		scheme = "http"
	}
	endpoint := (&url.URL{Scheme: scheme, Host: net.JoinHostPort(h.Address, strconv.Itoa(h.EffectivePort())), Path: "/wsman"}).String()
	cl.Win = &winrmShell{c: winrm.New(winrm.Config{Endpoint: endpoint, User: h.User, Password: pass, Basic: opts.Auth == "basic",
		TLS: tc, Dial: dial}), host: h}
	return cl, nil
}

func winrmOpts(h *store.Host) store.WinRMOpts {
	if h.WinRMOpts == nil {
		return store.WinRMOpts{}
	}
	return *h.WinRMOpts
}

// winrmPassword is the host's password: WinRM logs in with a password
// (NTLM or Basic), never with an SSH key.
func winrmPassword(h *store.Host) (string, error) {
	if h.PasswordRef == "" || h.User == "" {
		return "", out.Errf(out.ExitConnect, "AUTH_FAILED",
			"WinRM logs in with a user and a password: `komando host edit "+h.Name+" --ask-password` (and the user in the address, e.g. winrm://Administrator@HOST)",
			"%s has no user or password for WinRM", h.Name)
	}
	return vault.Resolve(h.PasswordRef)
}

// winrmTLS checks the server's certificate against this computer's CAs,
// and the host's own CA (a PEM in the vault) when it has one. skip-verify
// turns the check off; only a person sets that (docs/features/windows.md).
func winrmTLS(h *store.Host) (*tls.Config, error) {
	opts := winrmOpts(h)
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: h.Address}
	switch {
	case opts.TLS == "skip-verify":
		tc.InsecureSkipVerify = true //nolint:gosec // the host says winrm tls=skip-verify
	case opts.CA != "":
		pem, err := vault.Resolve(opts.CA)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return nil, out.Errf(out.ExitUsage, "BAD_CA", "store the CA certificate (PEM) with `komando secret set NAME < ca.crt`",
				"%s: the WinRM CA %s holds no PEM certificate", h.Name, opts.CA)
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

// winrmShell is the WinShell of a host: it turns the client's errors into
// komando's error codes.
type winrmShell struct {
	c    *winrm.Client
	host *store.Host
}

func (w *winrmShell) Run(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	code, err := w.c.Run(ctx, command, stdin, stdout, stderr)
	if err == nil || ctx.Err() != nil {
		return code, err
	}
	return code, winrmErr(w.host, err)
}

func (w *winrmShell) Close() error { return w.c.Close() }

// winrmErr names what went wrong with a WinRM server, with the next step.
func winrmErr(h *store.Host, err error) error {
	var fe *winrm.Error
	var ce x509.CertificateInvalidError
	var ue x509.UnknownAuthorityError
	var he x509.HostnameError
	var oe *net.OpError
	switch {
	case errors.Is(err, winrm.ErrAuth):
		return out.Errf(out.ExitConnect, "AUTH_FAILED", "check the user and password (`komando host edit "+h.Name+" --ask-password`); a domain user is written DOMAIN\\user; Basic login works only for local accounts",
			"%s: %v", h.Name, err)
	case errors.As(err, &ue), errors.As(err, &ce), errors.As(err, &he):
		return out.Errf(out.ExitConnect, "WINRM_TLS", "if the server's certificate comes from your own CA, store it with `komando secret set NAME < ca.crt` and add ?ca=secret:NAME to its winrm:// address (`komando host edit "+h.Name+" --address winrm://...`)",
			"%s: the WinRM server's certificate cannot be trusted: %v", h.Name, err)
	case errors.As(err, &fe):
		return out.Errf(out.ExitRemote, "WINRM_ERROR", "read the message; `winrm quickconfig` on the server sets WinRM up, and the user must be allowed to use it (an administrator, or the Remote Management Users group)",
			"%s: %v", h.Name, err)
	case errors.As(err, &oe) && oe.Op == "dial":
		return out.Errf(out.ExitConnect, "WINRM_UNREACHABLE", "check the address and that WinRM listens there (port 5986 for HTTPS, 5985 for HTTP) and the firewall lets you in",
			"cannot reach %s over WinRM: %v", h.Name, err)
	}
	if strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		return out.Errf(out.ExitConnect, "WINRM_NOT_HTTPS", "the server speaks plain HTTP there: use port 5986 for HTTPS, or ?tls=off if it truly has no HTTPS (commands then travel unencrypted)",
			"%s: %v", h.Name, err)
	}
	return err
}
