package proxyx_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/proxyx"
	"github.com/sgnd/komando/internal/proxyx/proxytest"
)

func pick(t *testing.T, f proxyx.Func, target string) string {
	t.Helper()
	u, _ := url.Parse(target)
	p, err := f(&http.Request{URL: u})
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		return ""
	}
	return p.String()
}

func TestFromEnv(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.corp:3128")
	t.Setenv("HTTP_PROXY", "http://plain.corp:8080")
	t.Setenv("NO_PROXY", ".internal,10.0.0.0/8")
	f := proxyx.FromEnv()
	for target, want := range map[string]string{
		"https://api.example.com:6443": "http://proxy.corp:3128",
		"http://registry.example.com":  "http://plain.corp:8080",
		"https://k8s.internal":         "",
		"https://10.1.2.3:6443":        "",
		"https://127.0.0.1:41234":      "", // a tunnel on this computer
		"https://localhost:5000":       "",
	} {
		if got := pick(t, f, target); got != want {
			t.Errorf("%s: proxy %q, want %q", target, got, want)
		}
	}
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "")
	if got := pick(t, proxyx.FromEnv(), "https://api.example.com"); got != "" {
		t.Errorf("without the variables there is no proxy, got %q", got)
	}
}

func TestParse(t *testing.T) {
	for _, ok := range []string{"http://proxy:3128", "https://u:p@proxy.example.com", "socks5://127.0.0.1:1080", "socks5h://proxy:1080"} {
		if _, err := proxyx.Parse(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "proxy:3128", "ftp://proxy:21", "http://", "://x"} {
		if _, err := proxyx.Parse(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

// echo answers each line with the same line.
func echo(t *testing.T) string {
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
				r := bufio.NewReader(c)
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					c.Write([]byte(l))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

var direct = (&net.Dialer{Timeout: 5 * time.Second}).DialContext

func TestDialThroughProxy(t *testing.T) {
	backend := echo(t)
	p := proxytest.Start(t, backend, http.StatusOK)
	pu, _ := url.Parse(p.URL)
	pu.User = url.UserPassword("me", "s3cret")
	target, _ := url.Parse("https://vpn.example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := proxyx.Dial(ctx, http.ProxyURL(pu), direct, target, "vpn.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello\n"))
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || got != "hello\n" {
		t.Fatalf("tunnel answered %q, %v", got, err)
	}
	if h := p.Hosts(); !slices.Equal(h, []string{"vpn.example.com:443"}) {
		t.Errorf("proxy was asked for %v", h)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("me:s3cret"))
	if a := p.Auth(); len(a) != 1 || a[0] != want {
		t.Errorf("Proxy-Authorization %v", a)
	}
}

func TestDialWithoutProxy(t *testing.T) {
	backend := echo(t)
	target, _ := url.Parse("https://" + backend)
	for _, f := range []proxyx.Func{nil, func(*http.Request) (*url.URL, error) { return nil, nil }} {
		c, err := proxyx.Dial(context.Background(), f, direct, target, backend)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
}

func TestDialRefused(t *testing.T) {
	p := proxytest.Start(t, echo(t), http.StatusProxyAuthRequired)
	pu, _ := url.Parse(p.URL)
	target, _ := url.Parse("https://vpn.example.com")
	_, err := proxyx.Dial(context.Background(), http.ProxyURL(pu), direct, target, "vpn.example.com:443")
	if err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("want the proxy's 407, got %v", err)
	}
	pu.User = url.UserPassword("me", "s3cret")
	_, err = proxyx.Dial(context.Background(), http.ProxyURL(pu), direct, target, "vpn.example.com:443")
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("the error must not show the proxy password: %v", err)
	}
}
