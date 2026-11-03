package sslvpn

import (
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
	"strings"
	"sync"
	"time"
)

// Fortinet SSL VPN (FortiGate): a form login (/remote/logincheck, with a
// token code asked from a person), the tunnel config
// (/remote/fortisslvpn_xml), then PPP frames inside TLS, each behind a
// 6-byte header: total length, 0x5050, payload length.

// FortinetLogin logs in and returns the SVPNCOOKIE value.
func FortinetLogin(ctx context.Context, o Options) (string, error) {
	u, err := portalURL(o.Portal)
	if err != nil {
		return "", err
	}
	hc, err := httpClient(o, u.Hostname())
	if err != nil {
		return "", err
	}
	realm := u.Query().Get("realm")
	form := url.Values{"ajax": {"1"}, "username": {o.User}, "realm": {realm}, "credential": {o.Password}}
	for round := 0; round < 4; round++ {
		req, _ := http.NewRequestWithContext(ctx, "POST", u.Scheme+"://"+u.Host+"/remote/logincheck", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := hc.Do(req)
		if err != nil {
			return "", err
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		for _, ck := range hc.Jar.Cookies(u) {
			if ck.Name == "SVPNCOOKIE" && ck.Value != "" {
				return ck.Value, nil
			}
		}
		fields := map[string]string{}
		for _, kv := range strings.Split(strings.TrimSpace(string(b)), ",") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				fields[k] = v
			}
		}
		if _, token := fields["tokeninfo"]; token || fields["ret"] == "2" {
			if o.Prompt == nil {
				return "", ErrNeedsPerson
			}
			code, err := o.Prompt("Token code", false)
			if err != nil {
				return "", err
			}
			form = url.Values{"ajax": {"1"}, "username": {o.User}, "realm": {realm}, "code": {code}, "code2": {""},
				"reqid": {fields["reqid"]}, "polid": {fields["polid"]}, "grp": {fields["grp"]}, "magic": {fields["magic"]}}
			continue
		}
		return "", &LoginError{Msg: "the VPN refused the login"}
	}
	return "", &LoginError{Msg: "the VPN gave no session cookie (SVPNCOOKIE)"}
}

type fortiConfig struct {
	IPv4 struct {
		DNS []struct {
			IP string `xml:"ip,attr"`
		} `xml:"dns"`
		Assigned struct {
			IP string `xml:"ipv4,attr"`
		} `xml:"assigned-addr"`
	} `xml:"ipv4"`
}

type fortiTun struct {
	base
	c   *tls.Conn
	wmu sync.Mutex
	ppp *ppp
}

// FortinetTunnel opens the tunnel with a session cookie.
func FortinetTunnel(ctx context.Context, o Options, cookie string) (Tunnel, error) {
	u, err := portalURL(o.Portal)
	if err != nil {
		return nil, err
	}
	hc, err := httpClient(o, u.Hostname())
	if err != nil {
		return nil, err
	}
	hc.Jar.SetCookies(u, []*http.Cookie{{Name: "SVPNCOOKIE", Value: cookie}})
	var cfg fortiConfig
	req, _ := http.NewRequestWithContext(ctx, "GET", u.Scheme+"://"+u.Host+"/remote/fortisslvpn_xml", nil)
	if resp, err := hc.Do(req); err == nil {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			_ = xml.Unmarshal(b, &cfg)
		} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, &LoginError{Msg: "the session cookie was refused; log in again"}
		}
	}
	c, err := dialTLS(ctx, o, u)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte("GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: " + u.Host + "\r\nCookie: SVPNCOOKIE=" + cookie + "\r\n\r\n")); err != nil {
		c.Close()
		return nil, err
	}
	t := &fortiTun{base: newBase(), c: c}
	t.closeFn = func() { c.Close() }
	t.ppp = newPPP(t.sendPPP)
	if a, err := netip.ParseAddr(cfg.IPv4.Assigned.IP); err == nil {
		t.ppp.addr = a
	}
	for _, d := range cfg.IPv4.DNS {
		if a, err := netip.ParseAddr(d.IP); err == nil {
			t.ppp.dns = append(t.ppp.dns, a)
		}
	}
	go t.read()
	if err := t.ppp.start(); err != nil {
		t.Close()
		return nil, err
	}
	if err := t.ppp.wait(30 * time.Second); err != nil {
		t.Close()
		return nil, err
	}
	addr, dns := t.ppp.result()
	t.addrs, t.dns = []netip.Addr{addr}, dns
	return t, nil
}

// sendPPP frames one PPP packet: header, then address/control and protocol.
func (t *fortiTun) sendPPP(proto uint16, data []byte) error {
	frame := append([]byte{0xff, 0x03, byte(proto >> 8), byte(proto)}, data...)
	b := make([]byte, 6, 6+len(frame))
	binary.BigEndian.PutUint16(b, uint16(6+len(frame)))
	b[2], b[3] = 0x50, 0x50
	binary.BigEndian.PutUint16(b[4:], uint16(len(frame)))
	b = append(b, frame...)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_, err := t.c.Write(b)
	return err
}

func (t *fortiTun) WritePacket(p []byte) error { return t.sendPPP(pppIPv4, p) }

func (t *fortiTun) Close() error { t.end(net.ErrClosed); return nil }

func (t *fortiTun) read() {
	hdr := make([]byte, 6)
	for {
		if _, err := io.ReadFull(t.c, hdr); err != nil {
			t.end(fmt.Errorf("connection to the VPN lost: %w", err))
			return
		}
		if hdr[2] != 0x50 || hdr[3] != 0x50 {
			if string(hdr[:4]) == "HTTP" {
				t.end(&LoginError{Msg: "the VPN refused the tunnel (log in again)"})
			} else {
				t.end(errors.New("the VPN sent a broken frame"))
			}
			return
		}
		frame := make([]byte, binary.BigEndian.Uint16(hdr[4:]))
		if _, err := io.ReadFull(t.c, frame); err != nil {
			t.end(err)
			return
		}
		if len(frame) >= 2 && frame[0] == 0xff && frame[1] == 0x03 {
			frame = frame[2:]
		}
		if len(frame) < 2 {
			continue
		}
		proto := binary.BigEndian.Uint16(frame)
		if proto == pppIPv4 {
			t.deliver(frame[2:])
			continue
		}
		if err := t.ppp.handle(proto, frame[2:]); err != nil {
			t.end(err)
			return
		}
	}
}
