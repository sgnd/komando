// Package sslvpn holds komando's own clients for corporate SSL VPNs:
// Cisco AnyConnect / ocserv, Fortinet, Palo Alto GlobalProtect, F5 BIG-IP
// and Pulse/Ivanti. Each logs in over HTTPS (Pulse: EAP inside IF-T/TLS),
// then carries IP packets over a TLS connection (AnyConnect also over
// DTLS); komando feeds them to a userspace network stack, so the
// computer's network is not changed and no openconnect is needed.
//
// The clients are written from the vendors' public behaviour and protocol
// write-ups; no code from openconnect (LGPL) or openfortivpn (GPL) is
// used. MFA and browser (SAML) logins stay with a person.
package sslvpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/proxyx"
)

// Tunnel is a connected VPN: IP packets in and out.
type Tunnel interface {
	WritePacket([]byte) error
	Packets() <-chan []byte
	Done() <-chan struct{}
	Err() error
	Close() error
	Addresses() []netip.Addr
	DNS() []netip.Addr
	MTU() int
}

// Options are what a client needs to log in.
type Options struct {
	Portal   string // host, host:port or https URL
	User     string
	Password string
	// Prompt asks a person for another answer (a one-time code, a
	// group); nil means nobody is there, so such a login fails.
	Prompt func(label string, secret bool) (string, error)
	// Dial reaches the portal (nil: directly).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Insecure skips certificate checks only when the profile asked for it.
	CA []byte
}

// LoginError is a login the server refused or that needs a person.
type LoginError struct{ Msg string }

func (e *LoginError) Error() string { return e.Msg }

// ErrNeedsPerson: the login asks for something only a person can give.
var ErrNeedsPerson = errors.New("the VPN login needs a person (a one-time code or browser sign-in); run `komando vpn up NAME`")

func portalURL(p string) (*url.URL, error) {
	if !strings.Contains(p, "://") {
		p = "https://" + p
	}
	u, err := url.Parse(p)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("bad portal %q", p)
	}
	if u.Scheme != "https" {
		return nil, errors.New("the portal must be https")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func tlsConfig(o Options, host string) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if len(o.CA) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(o.CA) {
			return nil, errors.New("the CA file holds no certificate")
		}
		tc.RootCAs = pool
	}
	return tc, nil
}

func httpClient(o Options, host string) (*http.Client, error) {
	tc, err := tlsConfig(o, host)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: tc, TLSHandshakeTimeout: 20 * time.Second, ForceAttemptHTTP2: false}
	if o.Dial != nil {
		tr.DialContext = o.Dial // the --via path is the way out
	} else {
		tr.Proxy = proxyx.FromEnv() // a company proxy: HTTPS_PROXY and NO_PROXY
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{Transport: tr, Jar: jar, Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 10 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("the portal redirects to plain http")
			}
			return nil
		}}, nil
}

// dialTLS opens the TLS connection that carries the tunnel.
func dialTLS(ctx context.Context, o Options, u *url.URL) (*tls.Conn, error) {
	return dialTLSWith(ctx, o, u, nil)
}

// dialTLSWith is dialTLS that also keeps, in keys, what an RFC 5705
// exporter needs for TLS 1.2 (see tlskeys.go).
func dialTLSWith(ctx context.Context, o Options, u *url.URL, keys *tlsKeys) (*tls.Conn, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	tc, err := tlsConfig(o, host)
	if err != nil {
		return nil, err
	}
	dial, pick := o.Dial, proxyx.Func(nil)
	if dial == nil {
		dial, pick = (&net.Dialer{Timeout: 20 * time.Second}).DialContext, proxyx.FromEnv()
	}
	raw, err := proxyx.Dial(ctx, pick, dial, u, net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	if keys != nil {
		tc.KeyLogWriter = keys
		raw = &helloSniffer{Conn: raw, keys: keys}
	}
	c := tls.Client(raw, tc)
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// base holds what every tunnel shares.
type base struct {
	packets chan []byte
	done    chan struct{}
	addrs   []netip.Addr
	dns     []netip.Addr
	mtu     int
	closeFn func()

	// end can race: the read or keepalive goroutine and Close may end
	// the tunnel at the same moment
	once sync.Once
	mu   sync.Mutex
	err  error
}

func newBase() base {
	return base{packets: make(chan []byte, 256), done: make(chan struct{}), mtu: 1400}
}

func (b *base) Packets() <-chan []byte { return b.packets }
func (b *base) Done() <-chan struct{}  { return b.done }
func (b *base) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}
func (b *base) Addresses() []netip.Addr { return b.addrs }
func (b *base) DNS() []netip.Addr       { return b.dns }
func (b *base) MTU() int                { return b.mtu }

func (b *base) end(err error) {
	b.once.Do(func() {
		b.mu.Lock()
		b.err = err
		b.mu.Unlock()
		close(b.done)
		if b.closeFn != nil {
			b.closeFn()
		}
	})
}

func (b *base) deliver(p []byte) {
	select {
	case b.packets <- p:
	default:
	}
}
