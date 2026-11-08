// Package proxyx sends komando's HTTPS clients through the company proxy
// that the environment names (HTTPS_PROXY, HTTP_PROXY, NO_PROXY), as curl,
// kubectl and docker do. It also opens raw TCP tunnels through that proxy
// for the connections http.Transport does not make itself (stream
// upgrades, SSL VPN tunnels).
//
// A connection that goes through a --via path never uses these proxies:
// the path is its way out.
package proxyx

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/proxy"
)

// Func picks the proxy for a request; a nil URL means none.
type Func = func(*http.Request) (*url.URL, error)

// Dialer opens TCP connections.
type Dialer = func(ctx context.Context, network, addr string) (net.Conn, error)

// FromEnv reads HTTPS_PROXY, HTTP_PROXY and NO_PROXY (or their lower-case
// names) now. Requests to this computer (localhost, 127.0.0.1, a tunnel's
// port) never use a proxy.
func FromEnv() Func {
	pick := httpproxy.FromEnvironment().ProxyFunc()
	return func(r *http.Request) (*url.URL, error) { return pick(r.URL) }
}

// Parse checks a proxy URL written in a config file, such as a
// kubeconfig's proxy-url.
func Parse(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%q is not a proxy URL like http://proxy.example.com:3128", raw)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
		return u, nil
	}
	return nil, fmt.Errorf("%q: a proxy URL starts with http://, https:// or socks5://", raw)
}

// Dial opens a TCP connection to addr (the host:port of target) through
// the proxy that pick chooses for target, or straight with dial when pick
// is nil or chooses none. dial also reaches the proxy.
func Dial(ctx context.Context, pick Func, dial Dialer, target *url.URL, addr string) (net.Conn, error) {
	var p *url.URL
	if pick != nil {
		var err error
		if p, err = pick(&http.Request{URL: target, Header: http.Header{}}); err != nil {
			return nil, err
		}
	}
	switch {
	case p == nil:
		return dial(ctx, "tcp", addr)
	case p.Scheme == "socks5" || p.Scheme == "socks5h":
		d, err := proxy.FromURL(p, ctxDialer(dial))
		if err != nil {
			return nil, err
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("SOCKS dialer without context support")
		}
		return cd.DialContext(ctx, "tcp", addr)
	}
	return connect(ctx, p, addr, dial)
}

// connect asks an HTTP proxy for a tunnel to addr (CONNECT).
func connect(ctx context.Context, p *url.URL, addr string, dial Dialer) (net.Conn, error) {
	host := p.Host
	if p.Port() == "" {
		port := "80"
		if p.Scheme == "https" {
			port = "443"
		}
		host = net.JoinHostPort(p.Hostname(), port)
	}
	conn, err := dial(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", p.Redacted(), err)
	}
	if p.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: p.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy %s: %w", p.Redacted(), err)
		}
		conn = tc
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
	if u := p.User; u != nil {
		pw, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)))
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	br := bufio.NewReader(conn)
	resp, err := roundTrip(conn, br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy %s: %w", p.Redacted(), err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy %s refused the tunnel to %s: %s", p.Redacted(), addr, resp.Status)
	}
	if br.Buffered() > 0 { // the far end may not speak before we do
		conn.Close()
		return nil, fmt.Errorf("proxy %s sent data before the tunnel was used", p.Redacted())
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func roundTrip(conn net.Conn, br *bufio.Reader, req *http.Request) (*http.Response, error) {
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(br, req)
}

// ctxDialer lets a Dialer serve as x/net/proxy's forward dialer.
type ctxDialer Dialer

func (d ctxDialer) Dial(network, addr string) (net.Conn, error) {
	return d(context.Background(), network, addr)
}

func (d ctxDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d(ctx, network, addr)
}
