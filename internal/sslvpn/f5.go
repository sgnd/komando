package sslvpn

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
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

// F5 BIG-IP Access Policy Manager: a form login (/my.policy, MRHSession
// cookie), the VPN resource from /vdesk, then /myvpn with PPP frames inside
// TLS, each behind a 4-byte header: f5 00 and the frame length.

// F5Login logs in and returns "MRHSession|resource|Z".
func F5Login(ctx context.Context, o Options) (string, error) {
	u, err := portalURL(o.Portal)
	if err != nil {
		return "", err
	}
	hc, err := httpClient(o, u.Hostname())
	if err != nil {
		return "", err
	}
	base := u.Scheme + "://" + u.Host
	get := func(path string) ([]byte, *http.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, "GET", base+path, nil)
		resp, err := hc.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return b, resp, err
	}
	if _, _, err := get("/"); err != nil { // the login page sets the first cookies
		return "", err
	}
	form := url.Values{"username": {o.User}, "password": {o.Password}, "vhost": {"standard"}}
	for round := 0; round < 4; round++ {
		req, _ := http.NewRequestWithContext(ctx, "POST", base+"/my.policy", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := hc.Do(req)
		if err != nil {
			return "", err
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if strings.Contains(string(b), `name="_F5_challenge"`) || strings.Contains(string(b), "otp") && strings.Contains(string(b), "<form") {
			if o.Prompt == nil {
				return "", ErrNeedsPerson
			}
			code, err := o.Prompt("One-time code", false)
			if err != nil {
				return "", err
			}
			form = url.Values{"_F5_challenge": {code}, "vhost": {"standard"}}
			continue
		}
		break
	}
	var session string
	for _, ck := range hc.Jar.Cookies(u) {
		if ck.Name == "MRHSession" {
			session = ck.Value
		}
	}
	if session == "" || session == "deleted" {
		return "", &LoginError{Msg: "the VPN refused the login"}
	}
	b, _, err := get("/vdesk/vpn/index.php3?outform=xml&client_version=2.0")
	if err != nil {
		return "", err
	}
	var fav struct {
		Favorites []struct {
			ID string `xml:"id,attr"`
		} `xml:"favorite"`
	}
	if err := xml.Unmarshal(b, &fav); err != nil || len(fav.Favorites) == 0 {
		return "", errors.New("the VPN offers no network access resource")
	}
	res := fav.Favorites[0].ID
	b, _, err = get("/vdesk/vpn/connect.php3?" + url.Values{"resourcename": {res}, "outform": {"xml"}, "client_version": {"2.0"}}.Encode())
	if err != nil {
		return "", err
	}
	var obj struct {
		Z string `xml:"object>ur_Z"`
	}
	if err := xml.Unmarshal(b, &obj); err != nil || obj.Z == "" {
		return "", errors.New("the VPN gave no tunnel session (ur_Z)")
	}
	return session + "|" + res + "|" + obj.Z, nil
}

type f5Tun struct {
	base
	c   *tls.Conn
	br  *bufio.Reader
	wmu sync.Mutex
	ppp *ppp
}

// F5Tunnel opens the tunnel with what F5Login returned.
func F5Tunnel(ctx context.Context, o Options, login string) (Tunnel, error) {
	parts := strings.SplitN(login, "|", 3)
	if len(parts) != 3 {
		return nil, errors.New("not an F5 session")
	}
	session, z := parts[0], parts[2]
	u, err := portalURL(o.Portal)
	if err != nil {
		return nil, err
	}
	c, err := dialTLS(ctx, o, u)
	if err != nil {
		return nil, err
	}
	q := url.Values{"sess": {z}, "hostname": {base64.StdEncoding.EncodeToString([]byte("komando"))}, "hdlc_framing": {"no"},
		"ipv4": {"yes"}, "ipv6": {"no"}, "Z": {z}}
	if _, err := c.Write([]byte("GET /myvpn?" + q.Encode() + " HTTP/1.1\r\nHost: " + u.Host + "\r\nCookie: MRHSession=" + session + "\r\n\r\n")); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, &LoginError{Msg: "the VPN refused the tunnel: " + resp.Status}
	}
	t := &f5Tun{base: newBase(), c: c, br: br}
	t.closeFn = func() { c.Close() }
	t.ppp = newPPP(t.sendPPP)
	if a, err := netip.ParseAddr(resp.Header.Get("X-VPN-client-IP")); err == nil {
		t.ppp.addr = a
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

func (t *f5Tun) sendPPP(proto uint16, data []byte) error {
	frame := append([]byte{0xff, 0x03, byte(proto >> 8), byte(proto)}, data...)
	b := make([]byte, 4, 4+len(frame))
	b[0], b[1] = 0xf5, 0x00
	binary.BigEndian.PutUint16(b[2:], uint16(len(frame)))
	b = append(b, frame...)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_, err := t.c.Write(b)
	return err
}

func (t *f5Tun) WritePacket(p []byte) error { return t.sendPPP(pppIPv4, p) }

func (t *f5Tun) Close() error { t.end(net.ErrClosed); return nil }

func (t *f5Tun) read() {
	hdr := make([]byte, 4)
	for {
		if _, err := io.ReadFull(t.br, hdr); err != nil {
			t.end(fmt.Errorf("connection to the VPN lost: %w", err))
			return
		}
		if hdr[0] != 0xf5 || hdr[1] != 0x00 {
			t.end(errors.New("the VPN sent a broken frame"))
			return
		}
		frame := make([]byte, binary.BigEndian.Uint16(hdr[2:]))
		if _, err := io.ReadFull(t.br, frame); err != nil {
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
