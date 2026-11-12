package netx

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/proxyx"
	"github.com/sgnd/komando/internal/store"
)

// openHTTPProxy is a "proxy" VPN: an HTTP proxy that tunnels each TCP
// connection (CONNECT), as company networks use to let traffic out. Any
// target can use it with --via: servers, databases, caches, file servers.
func openHTTPProxy(v *store.Vpn, timeout time.Duration) (Dialer, io.Closer, error) {
	pu, err := ProxyURL(v.Address)
	if err != nil {
		return nil, nil, configErr(v, err)
	}
	if v.User != "" {
		pw, err := secret(v, v.KeyRef)
		if err != nil {
			return nil, nil, err
		}
		pu.User = url.UserPassword(v.User, pw)
	}
	pick := http.ProxyURL(pu)
	direct := (&net.Dialer{Timeout: timeout}).DialContext
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := proxyx.Dial(ctx, pick, direct, &url.URL{Scheme: "https", Host: addr}, addr)
		if err != nil {
			return nil, Down(v, err)
		}
		return c, nil
	}, nopCloser{}, nil
}

// ProxyURL reads a proxy VPN's --address: host:port (plain HTTP to the
// proxy) or an http:// or https:// URL.
func ProxyURL(address string) (*url.URL, error) {
	a := strings.TrimSpace(address)
	if !strings.Contains(a, "://") {
		if _, _, err := net.SplitHostPort(a); err != nil {
			return nil, fmt.Errorf("--address takes HOST:PORT or an http(s):// URL, not %q", address)
		}
		a = "http://" + a
	}
	u, err := proxyx.Parse(a)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("a proxy VPN is an HTTP proxy (http:// or https://); for SOCKS add a socks VPN")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}
