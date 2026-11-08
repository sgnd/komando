package netx

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/proxyx/proxytest"
	"github.com/sgnd/komando/internal/store"
)

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				l, _ := bufio.NewReader(c).ReadString('\n')
				c.Write([]byte("echo " + l))
			}()
		}
	}()
	return ln.Addr().String()
}

// A proxy VPN tunnels each connection through the HTTP proxy (CONNECT),
// with its login when it has one.
func TestHTTPProxyVPN(t *testing.T) {
	p := proxytest.Start(t, echoServer(t), http.StatusOK)
	t.Setenv("KOMANDO_TEST_PROXY_PW", "s3cret")
	v := &store.Vpn{Name: "corp", Kind: "proxy", Address: p.URL, User: "me", KeyRef: "env:KOMANDO_TEST_PROXY_PW"}
	dial, closer, err := OpenDirect(context.Background(), v, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	c, err := dial(context.Background(), "tcp", "db.internal:5432")
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hello\n"))
	got, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if got != "echo hello\n" {
		t.Errorf("through the proxy: %q", got)
	}
	if h := p.Hosts(); len(h) != 1 || h[0] != "db.internal:5432" {
		t.Errorf("the proxy was asked for %v", h)
	}
	if a := p.Auth(); a[0] != "Basic "+base64.StdEncoding.EncodeToString([]byte("me:s3cret")) {
		t.Errorf("login: %v", a)
	}
}

func TestHTTPProxyVPNRefused(t *testing.T) {
	p := proxytest.Start(t, echoServer(t), http.StatusForbidden)
	v := &store.Vpn{Name: "corp", Kind: "proxy", Address: p.URL}
	dial, _, err := OpenDirect(context.Background(), v, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = dial(context.Background(), "tcp", "db.internal:5432")
	oe, ok := err.(*out.Error)
	if !ok || oe.Code != "VPN_DOWN" || !strings.Contains(oe.Message, "403") || !strings.Contains(oe.Hint, "443") {
		t.Errorf("a refused tunnel: %v", err)
	}
}

func TestProxyURL(t *testing.T) {
	for in, want := range map[string]string{
		"proxy.corp:3128":            "http://proxy.corp:3128",
		"http://proxy.corp:3128":     "http://proxy.corp:3128",
		"https://proxy.corp":         "https://proxy.corp",
		"http://u:p@proxy.corp:3128": "http://proxy.corp:3128", // a login goes in --user and --password-ref
	} {
		u, err := ProxyURL(in)
		if err != nil || u.String() != want {
			t.Errorf("%s: %v %v, want %s", in, u, err, want)
		}
	}
	for _, bad := range []string{"proxy.corp", "socks5://proxy:1080", "ftp://proxy:21", ""} {
		if _, err := ProxyURL(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}
