package sslvpn

import (
	"bufio"
	"bytes"
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
	"sync/atomic"
	"time"
)

// AnyConnect speaks the Cisco AnyConnect protocol (as ocserv and Cisco ASA
// serve it): XML "aggregate auth" to log in, then CSTP frames over TLS,
// and DTLS over UDP where the server offers it (anyconnect_dtls.go).

const acUserAgent = "AnyConnect Linux_64 4.10.07061"

type acForm struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"`
	Opaque  *struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"opaque"`
	Auth struct {
		ID      string `xml:"id,attr"`
		Message string `xml:"message"`
		Error   *struct {
			Text string `xml:",chardata"`
		} `xml:"error"`
		Form struct {
			Action string `xml:"action,attr"`
			Inputs []struct {
				Type  string `xml:"type,attr"`
				Name  string `xml:"name,attr"`
				Label string `xml:"label,attr"`
				Value string `xml:"value,attr"`
			} `xml:"input"`
			Selects []struct {
				Name    string `xml:"name,attr"`
				Label   string `xml:"label,attr"`
				Options []struct {
					Value string `xml:"value,attr"`
					Text  string `xml:",chardata"`
				} `xml:"option"`
			} `xml:"select"`
		} `xml:"form"`
	} `xml:"auth"`
	SessionToken string `xml:"session-token"`
}

func acXML(typ string, inner string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="` + typ + `" aggregate-auth-version="2">
<version who="vpn">v9.0</version>
<device-id>linux-64</device-id>
` + inner + `
</config-auth>`)
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// AnyConnect logs in and opens the tunnel.
func AnyConnect(ctx context.Context, o Options) (Tunnel, error) {
	cookie, err := AnyConnectLogin(ctx, o)
	if err != nil {
		return nil, err
	}
	return AnyConnectTunnel(ctx, o, cookie)
}

// AnyConnectLogin logs in (asking o.Prompt for what a person must answer)
// and returns the session cookie the tunnel needs.
func AnyConnectLogin(ctx context.Context, o Options) (string, error) {
	u, err := portalURL(o.Portal)
	if err != nil {
		return "", err
	}
	portal := *u
	hc, err := httpClient(o, u.Hostname())
	if err != nil {
		return "", err
	}
	post := func(body []byte) (*acForm, *http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("User-Agent", acUserAgent)
		req.Header.Set("X-Transcend-Version", "1")
		req.Header.Set("X-Aggregate-Auth", "1")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := hc.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			return nil, resp, fmt.Errorf("the portal answered %s", resp.Status)
		}
		var f acForm
		if err := xml.Unmarshal(b, &f); err != nil {
			return nil, resp, fmt.Errorf("the portal did not answer like AnyConnect: %w", err)
		}
		return &f, resp, nil
	}
	f, _, err := post(acXML("init", "<group-access>"+xmlEscape(u.String())+"</group-access>"))
	if err != nil {
		return "", err
	}
	usedPassword := false
	sent := map[string]bool{} // password fields already answered
	for round := 0; round < 8; round++ {
		switch f.Type {
		case "complete":
			return acCookie(hc, u, f.SessionToken)
		case "auth-request":
		default:
			return "", fmt.Errorf("unexpected AnyConnect answer %q", f.Type)
		}
		if f.Auth.Error != nil && strings.TrimSpace(f.Auth.Error.Text) != "" {
			return "", &LoginError{Msg: "the VPN refused the login: " + strings.TrimSpace(f.Auth.Error.Text)}
		}
		if f.Auth.Form.Action != "" {
			a, err := u.Parse(f.Auth.Form.Action)
			if err != nil {
				return "", fmt.Errorf("the portal sent a bad login form action %q", f.Auth.Form.Action)
			}
			// the login (with the stored password) goes only to the portal
			// itself, over https
			if !samePortal(portal, a) {
				return "", fmt.Errorf("the portal asked komando to send the login to %s://%s; komando only sends it to https://%s", a.Scheme, a.Host, portal.Host)
			}
			u = a
		}
		var fields strings.Builder
		for _, in := range f.Auth.Form.Inputs {
			v := in.Value
			switch {
			case in.Type == "submit" || in.Type == "hidden" && in.Name == "":
				continue
			case strings.EqualFold(in.Name, "username"):
				v = o.User
			case in.Type == "password" && sent[in.Name]:
				// the same field again: the answer was wrong
				return "", &LoginError{Msg: "the VPN refused the login (it asks for " + firstNonEmptyS(in.Label, in.Name) + " again)"}
			case in.Type == "password" && !usedPassword:
				v, usedPassword = o.Password, true
			case in.Type == "password" || in.Type == "text":
				if o.Prompt == nil {
					return "", ErrNeedsPerson
				}
				if v, err = o.Prompt(firstNonEmptyS(in.Label, in.Name), in.Type == "password"); err != nil {
					return "", err
				}
			}
			if in.Type == "password" {
				sent[in.Name] = true
			}
			fields.WriteString("<" + in.Name + ">" + xmlEscape(v) + "</" + in.Name + ">")
		}
		for _, s := range f.Auth.Form.Selects {
			v := ""
			if len(s.Options) > 0 {
				v = s.Options[0].Value
			}
			fields.WriteString("<" + s.Name + ">" + xmlEscape(v) + "</" + s.Name + ">")
		}
		opaque := ""
		if f.Opaque != nil {
			opaque = "<opaque is-for=\"sg\">" + string(f.Opaque.Inner) + "</opaque>"
		}
		f, _, err = post(acXML("auth-reply", opaque+"<auth>"+fields.String()+"</auth>"))
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("the AnyConnect login did not finish")
}

// samePortal reports whether a is the portal p over https (same host and
// port; 443 when none is given).
func samePortal(p url.URL, a *url.URL) bool {
	port := func(u *url.URL) string {
		if u.Port() == "" {
			return "443"
		}
		return u.Port()
	}
	return a.Scheme == "https" && strings.EqualFold(a.Hostname(), p.Hostname()) && port(a) == port(&p)
}

func firstNonEmptyS(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

type acTun struct {
	base
	c    *tls.Conn
	wmu  sync.Mutex
	dpd  time.Duration
	last time.Time
	lmu  sync.Mutex
	udp  atomic.Pointer[acDTLS] // the DTLS channel while it works
}

// CSTP frame: "STF" 0x01, length (2), type, 0
const (
	cstpData       = 0x00
	cstpDPDReq     = 0x03
	cstpDPDResp    = 0x04
	cstpDisconnect = 0x05
	cstpKeepalive  = 0x07
	cstpCompressed = 0x08
	cstpTerminate  = 0x09
)

func acCookie(hc *http.Client, u *url.URL, token string) (string, error) {
	cookie := token
	for _, ck := range hc.Jar.Cookies(u) {
		if ck.Name == "webvpn" {
			cookie = ck.Value
		}
	}
	if cookie == "" {
		return "", errors.New("the portal gave no session cookie")
	}
	return cookie, nil
}

// AnyConnectTunnel opens the CSTP tunnel with a session cookie.
func AnyConnectTunnel(ctx context.Context, o Options, cookie string) (Tunnel, error) {
	u, err := portalURL(o.Portal)
	if err != nil {
		return nil, err
	}
	keys := &tlsKeys{}
	c, err := dialTLSWith(ctx, o, u, keys)
	if err != nil {
		return nil, err
	}
	req := "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nHost: " + u.Host + "\r\nUser-Agent: " + acUserAgent +
		"\r\nCookie: webvpn=" + cookie + "\r\nX-CSTP-Version: 1\r\nX-CSTP-Hostname: komando\r\nX-CSTP-Address-Type: IPv6,IPv4" +
		"\r\nX-CSTP-MTU: 1399\r\nX-CSTP-Base-MTU: 1500\r\nX-CSTP-Accept-Encoding: identity" + dtlsHeaders() + "\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("the VPN refused the tunnel: %s", resp.Status)
	}
	t := &acTun{base: newBase(), c: c, last: time.Now()}
	h := resp.Header
	for _, a := range h.Values("X-CSTP-Address") {
		if ip, err := netip.ParseAddr(a); err == nil {
			t.addrs = append(t.addrs, ip)
		}
	}
	for _, a := range h.Values("X-CSTP-Address-IP6") {
		if p, err := netip.ParsePrefix(a); err == nil {
			t.addrs = append(t.addrs, p.Addr())
		}
	}
	for _, d := range h.Values("X-CSTP-DNS") {
		if ip, err := netip.ParseAddr(d); err == nil {
			t.dns = append(t.dns, ip)
		}
	}
	if n, err := strconv.Atoi(h.Get("X-CSTP-MTU")); err == nil && n > 576 {
		t.mtu = n
	}
	t.dpd = 30 * time.Second
	if n, err := strconv.Atoi(h.Get("X-CSTP-DPD")); err == nil && n > 0 {
		t.dpd = time.Duration(n) * time.Second
	}
	if len(t.addrs) == 0 {
		c.Close()
		return nil, errors.New("the VPN gave no address (X-CSTP-Address)")
	}
	addr, appID, dtlsDPD, useDTLS := dtlsOffer(h, u)
	if useDTLS && o.Dial == nil { // UDP goes direct; a tunnel through a jump host stays on TLS
		if n, err := strconv.Atoi(h.Get("X-DTLS-MTU")); err == nil && n > 576 && n < t.mtu {
			t.mtu = n // packets must fit either way
		}
	}
	t.closeFn = func() { c.Close() }
	go t.read(br)
	go t.keepalive()
	if useDTLS && o.Dial == nil {
		go t.startDTLS(c, keys, addr, appID, dtlsDPD, dtlsTimeout)
	}
	return t, nil
}

func (t *acTun) frame(typ byte, payload []byte) error {
	b := make([]byte, 8+len(payload))
	copy(b, "STF\x01")
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[6] = typ
	copy(b[8:], payload)
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_, err := t.c.Write(b)
	return err
}

func (t *acTun) WritePacket(p []byte) error {
	if d := t.udp.Load(); d != nil && d.send(cstpData, p) == nil {
		return nil
	}
	return t.frame(cstpData, p)
}

func (t *acTun) Close() error { t.end(net.ErrClosed); return nil }

func (t *acTun) read(br *bufio.Reader) {
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			t.end(fmt.Errorf("connection to the VPN lost: %w", err))
			return
		}
		if string(hdr[:4]) != "STF\x01" {
			t.end(errors.New("the VPN sent a broken frame"))
			return
		}
		p := make([]byte, binary.BigEndian.Uint16(hdr[4:]))
		if _, err := io.ReadFull(br, p); err != nil {
			t.end(err)
			return
		}
		t.lmu.Lock()
		t.last = time.Now()
		t.lmu.Unlock()
		switch hdr[6] {
		case cstpData:
			t.deliver(p)
		case cstpDPDReq:
			t.frame(cstpDPDResp, nil)
		case cstpDisconnect, cstpTerminate:
			t.end(errors.New("the VPN ended the session"))
			return
		case cstpCompressed:
			t.end(errors.New("the VPN sent a compressed packet, which komando refuses"))
			return
		}
	}
}

func (t *acTun) keepalive() {
	tick := time.NewTicker(t.dpd)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
		}
		t.lmu.Lock()
		idle := time.Since(t.last)
		t.lmu.Unlock()
		if idle > 3*t.dpd {
			t.end(errors.New("the VPN stopped answering (dead peer detection)"))
			return
		}
		t.frame(cstpDPDReq, nil)
	}
}
