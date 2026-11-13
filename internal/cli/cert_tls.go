package cli

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
	"time"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// certURLPorts are the default ports of TLS schemes.
var certURLPorts = map[string]string{"https": "443", "wss": "443", "smtps": "465", "imaps": "993", "pop3s": "995", "ldaps": "636", "ftps": "990"}

// parseCertURL reads a website target: a URL (https://name[:port]/...) or
// host:port. A name in the inventory, a selector or user@addr is not one.
func parseCertURL(st *store.State, s string) (addr, serverName string, ok bool, err error) {
	if strings.Contains(s, "://") {
		u, perr := url.Parse(s)
		if perr != nil || u.Hostname() == "" {
			return "", "", false, out.Usage("cannot read %q as a URL", s)
		}
		if sch := strings.ToLower(u.Scheme); sch == "http" || sch == "ws" {
			return "", "", false, out.Errf(out.ExitUsage, "USAGE", "for example: komando cert check https://"+u.Host,
				"%s has no certificate: %s is not encrypted", s, sch)
		}
		port := u.Port()
		if port == "" {
			if port = certURLPorts[strings.ToLower(u.Scheme)]; port == "" {
				return "", "", false, out.Usage("%s: give the port (%s:PORT), komando does not know the %s port", s, u.Hostname(), u.Scheme)
			}
		}
		return net.JoinHostPort(u.Hostname(), port), u.Hostname(), true, nil
	}
	if strings.ContainsAny(s, "@,!*") || strings.HasPrefix(s, "tag:") || strings.HasPrefix(s, "label:") || strings.HasPrefix(s, "kind:") {
		return "", "", false, nil
	}
	if _, ok := st.Hosts[s]; ok {
		return "", "", false, nil
	}
	if _, ok := st.Conns[s]; ok {
		return "", "", false, nil
	}
	host, port, serr := net.SplitHostPort(s)
	if serr != nil || host == "" {
		return "", "", false, nil
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 1 || n > 65535 {
		return "", "", false, nil
	}
	return s, host, true, nil
}

// certDialer is the way to the website: through the --via path, or direct.
func certDialer(ctx context.Context, st *store.State, via string) (netx.Dialer, io.Closer, error) {
	if via == "" {
		d := &net.Dialer{}
		return d.DialContext, nil, nil
	}
	h, vpn, err := resolveVia(st, via)
	if err != nil {
		return nil, nil, err
	}
	if vpn != nil {
		return netx.Open(ctx, vpn, sshOpts(st).ConnectTimeout)
	}
	cctx, cancel := context.WithTimeout(ctx, sshOpts(st).ConnectTimeout)
	defer cancel()
	c, err := sshx.Dial(cctx, st, h, sshOpts(st))
	if err != nil {
		return nil, nil, err
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := c.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return sshx.WithDeadlines(conn), nil
	}, c, nil
}

func checkServedCert(ctx context.Context, st *store.State, u certURL) (certInfo, error) {
	dial, closer, err := certDialer(ctx, st, u.via)
	if err != nil {
		return certInfo{}, err
	}
	if closer != nil {
		defer closer.Close()
	}
	return servedCert(ctx, dial, u.address, u.serverName, sshOpts(st).ConnectTimeout, u.via)
}

// servedCert connects, reads the chain the server sends and verifies it
// against the trust store and the name. The handshake itself skips the
// check so that an untrusted or expired certificate can still be shown.
func servedCert(ctx context.Context, dial netx.Dialer, address, serverName string, timeout time.Duration, via string) (certInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := dial(ctx, "tcp", address)
	if err != nil {
		return certInfo{}, certConnErr(address, via, err)
	}
	defer raw.Close()
	sni := serverName
	if net.ParseIP(sni) != nil {
		sni = ""
	}
	conn := tls.Client(raw, certTLSConfig(sni))
	if err := conn.HandshakeContext(ctx); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return certInfo{}, certConnErr(address, via, ctx.Err())
		}
		return certInfo{}, out.Errf(out.ExitConnect, "TLS_HANDSHAKE_FAILED", "the server ended the TLS handshake; run it again, and check that "+address+" is the TLS port (not plain HTTP)",
			"TLS handshake with %s failed: %v", address, err)
	}
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return certInfo{}, out.Errf(out.ExitRemote, "NO_CERTIFICATE", "check that "+address+" is the TLS port of the site", "%s sent no certificate", address)
	}
	ci := certFields(peers[0])
	ci.Sources, ci.Address, ci.Chain = []string{"url"}, address, len(peers)
	inter := x509.NewCertPool()
	for _, p := range peers[1:] {
		inter.AddCert(p)
	}
	ok := true
	if _, err := peers[0].Verify(x509.VerifyOptions{DNSName: serverName, Intermediates: inter, Roots: certRoots, CurrentTime: certNow()}); err != nil {
		ok = false
		ci.VerifyError = err.Error()
	}
	ci.Verified = &ok
	return ci, nil
}

// certTLSConfig skips the check in the handshake (servedCert verifies by
// hand, to report instead of fail) and offers only the classic key
// exchanges: some servers and middleboxes drop the large post-quantum
// hello Go sends by default, and reading a certificate needs none of it.
func certTLSConfig(sni string) *tls.Config {
	return &tls.Config{ServerName: sni, InsecureSkipVerify: true, //nolint:gosec // verified by hand in servedCert
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}}
}

func certConnErr(address, via string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "the port may be firewalled; check the address or raise --connect-timeout", "connecting to %s timed out", address)
	}
	hint := "check the name and port; if the site is only reachable from a server or VPN, add --via NAME"
	if via != "" {
		hint = "the address is reached through " + via + "; check it from there with `komando net check " + via + " " + address + "`"
	}
	return out.Errf(out.ExitConnect, "CONNECT_FAILED", hint, "cannot reach %s: %v", address, err)
}
