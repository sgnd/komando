package sslvpn

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Palo Alto GlobalProtect, gateway login: /ssl-vpn/login.esp (a challenge
// asks a person for a code), /ssl-vpn/getconfig.esp for the address, then
// the GPST tunnel inside TLS. Each frame: magic 1a2b3c4d, ethertype (0800),
// length, 8 bytes 01 00..., the IP packet. A frame with length 0 keeps the
// link alive. ESP over UDP is not used.

const gpUserAgent = "PAN GlobalProtect"

// GPSession is what the tunnel needs from a login.
type GPSession struct {
	User, AuthCookie, Portal, Domain, Computer string
}

// String packs the session for `komando vpn serve` (one line, no secrets
// beyond the cookie it already is).
func (s GPSession) String() string {
	return url.Values{"user": {s.User}, "authcookie": {s.AuthCookie}, "portal": {s.Portal}, "domain": {s.Domain}, "computer": {s.Computer}}.Encode()
}

// ParseGPSession is the reverse of GPSession.String.
func ParseGPSession(s string) (GPSession, error) {
	v, err := url.ParseQuery(s)
	if err != nil || v.Get("authcookie") == "" {
		return GPSession{}, errors.New("not a GlobalProtect session")
	}
	return GPSession{User: v.Get("user"), AuthCookie: v.Get("authcookie"), Portal: v.Get("portal"), Domain: v.Get("domain"), Computer: v.Get("computer")}, nil
}

// GlobalProtectLogin logs in to the gateway.
func GlobalProtectLogin(ctx context.Context, o Options) (GPSession, error) {
	u, err := portalURL(o.Portal)
	if err != nil {
		return GPSession{}, err
	}
	hc, err := httpClient(o, u.Hostname())
	if err != nil {
		return GPSession{}, err
	}
	form := url.Values{"prot": {"https:"}, "server": {u.Hostname()}, "inputStr": {""}, "jnlpReady": {"jnlpReady"},
		"user": {o.User}, "passwd": {o.Password}, "computer": {"komando"}, "ok": {"Login"}, "direct": {"yes"},
		"clientVer": {"4100"}, "os-version": {"Linux"}, "clientos": {"Linux"}, "portal-userauthcookie": {""}, "portal-prelogonuserauthcookie": {""}}
	for round := 0; round < 4; round++ {
		req, _ := http.NewRequestWithContext(ctx, "POST", u.Scheme+"://"+u.Host+"/ssl-vpn/login.esp", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", gpUserAgent)
		resp, err := hc.Do(req)
		if err != nil {
			return GPSession{}, err
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == 512 || bytes.Contains(b, []byte("Challenge")) || bytes.Contains(b, []byte("respStatus = \"Challenge\"")) {
			if o.Prompt == nil {
				return GPSession{}, ErrNeedsPerson
			}
			code, err := o.Prompt(gpChallengeText(b), false)
			if err != nil {
				return GPSession{}, err
			}
			form.Set("passwd", code)
			form.Set("inputStr", gpInputStr(b))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return GPSession{}, &LoginError{Msg: fmt.Sprintf("the VPN refused the login (%s)", resp.Status)}
		}
		s, err := parseGPLogin(b)
		if err != nil {
			return GPSession{}, err
		}
		s.User = cmp.Or(s.User, o.User)
		return s, nil
	}
	return GPSession{}, &LoginError{Msg: "the GlobalProtect login did not finish"}
}

// parseGPLogin reads the jnlp answer: an argument list whose positions
// carry the cookie, portal, user, domain and computer.
func parseGPLogin(b []byte) (GPSession, error) {
	var j struct {
		Args []string `xml:"application-desc>argument"`
	}
	if err := xml.Unmarshal(b, &j); err != nil || len(j.Args) < 5 {
		return GPSession{}, &LoginError{Msg: "the VPN refused the login"}
	}
	at := func(i int) string {
		if i < len(j.Args) {
			return strings.TrimSpace(j.Args[i])
		}
		return ""
	}
	s := GPSession{AuthCookie: at(1), Portal: at(3), User: at(4), Domain: at(7), Computer: "komando"}
	if s.AuthCookie == "" || s.AuthCookie == "(null)" {
		return GPSession{}, &LoginError{Msg: "the VPN gave no session cookie"}
	}
	return s, nil
}

func gpChallengeText(b []byte) string {
	if i := bytes.Index(b, []byte("respMsg = \"")); i >= 0 {
		rest := b[i+len("respMsg = \""):]
		if j := bytes.IndexByte(rest, '"'); j >= 0 {
			return string(rest[:j])
		}
	}
	return "Code"
}

func gpInputStr(b []byte) string {
	if i := bytes.Index(b, []byte("inputStr = \"")); i >= 0 {
		rest := b[i+len("inputStr = \""):]
		if j := bytes.IndexByte(rest, '"'); j >= 0 {
			return string(rest[:j])
		}
	}
	return ""
}

type gpTun struct {
	base
	c   *tls.Conn
	wmu sync.Mutex
}

// GlobalProtectTunnel reads the config and opens the tunnel.
func GlobalProtectTunnel(ctx context.Context, o Options, s GPSession) (Tunnel, error) {
	u, err := portalURL(o.Portal)
	if err != nil {
		return nil, err
	}
	hc, err := httpClient(o, u.Hostname())
	if err != nil {
		return nil, err
	}
	auth := url.Values{"user": {s.User}, "authcookie": {s.AuthCookie}, "portal": {s.Portal}, "domain": {s.Domain}, "computer": {s.Computer}}
	cfgForm := url.Values{"client-type": {"1"}, "protocol-version": {"p1"}, "app-version": {"4.1.0"}, "os-version": {"Linux"},
		"clientos": {"Linux"}, "hmac-algo": {"sha1,md5"}, "enc-algo": {"aes-128-cbc,aes-256-cbc"}, "preferred-ip": {""}}
	for k, v := range auth {
		cfgForm[k] = v
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", u.Scheme+"://"+u.Host+"/ssl-vpn/getconfig.esp", strings.NewReader(cfgForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", gpUserAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &LoginError{Msg: "the gateway refused the session; log in again (" + resp.Status + ")"}
	}
	var cfg struct {
		IP  string   `xml:"ip-address"`
		MTU string   `xml:"mtu"`
		DNS []string `xml:"dns>member"`
	}
	if err := xml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("the gateway's config: %w", err)
	}
	t := &gpTun{base: newBase()}
	if a, err := netip.ParseAddr(cfg.IP); err == nil {
		t.addrs = []netip.Addr{a}
	} else {
		return nil, errors.New("the gateway gave no address")
	}
	for _, d := range cfg.DNS {
		if a, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil {
			t.dns = append(t.dns, a)
		}
	}
	if n, err := strconv.Atoi(cfg.MTU); err == nil && n > 576 {
		t.mtu = n
	}
	c, err := dialTLS(ctx, o, u)
	if err != nil {
		return nil, err
	}
	t.c = c
	t.closeFn = func() { c.Close() }
	if _, err := c.Write([]byte("GET /ssl-tunnel-connect.sslvpn?" + url.Values{"user": {s.User}, "authcookie": {s.AuthCookie}}.Encode() + " HTTP/1.1\r\nHost: " + u.Host + "\r\n\r\n")); err != nil {
		c.Close()
		return nil, err
	}
	start := make([]byte, 12)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(c, start); err != nil {
		c.Close()
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	c.SetReadDeadline(time.Time{})
	if string(start) != "START_TUNNEL" {
		c.Close()
		return nil, &LoginError{Msg: "the gateway refused the tunnel: " + strings.TrimSpace(string(start))}
	}
	go t.read()
	go t.keepalive()
	return t, nil
}

func (t *gpTun) frame(p []byte) error {
	b := make([]byte, 16, 16+len(p))
	binary.BigEndian.PutUint32(b, 0x1a2b3c4d)
	binary.BigEndian.PutUint16(b[4:], 0x0800)
	binary.BigEndian.PutUint16(b[6:], uint16(len(p)))
	b[8] = 1
	b = append(b, p...)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_, err := t.c.Write(b)
	return err
}

func (t *gpTun) WritePacket(p []byte) error { return t.frame(p) }

func (t *gpTun) Close() error { t.end(net.ErrClosed); return nil }

func (t *gpTun) read() {
	hdr := make([]byte, 16)
	for {
		if _, err := io.ReadFull(t.c, hdr); err != nil {
			t.end(fmt.Errorf("connection to the VPN lost: %w", err))
			return
		}
		if binary.BigEndian.Uint32(hdr) != 0x1a2b3c4d {
			t.end(errors.New("the VPN sent a broken frame"))
			return
		}
		n := binary.BigEndian.Uint16(hdr[6:])
		if n == 0 {
			continue // keepalive
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(t.c, p); err != nil {
			t.end(err)
			return
		}
		if binary.BigEndian.Uint16(hdr[4:]) == 0x0800 {
			t.deliver(p)
		}
	}
}

func (t *gpTun) keepalive() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
			if err := t.frame(nil); err != nil {
				t.end(err)
				return
			}
		}
	}
}
