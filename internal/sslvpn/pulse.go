package sslvpn

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
)

// Pulse Secure / Ivanti Connect Secure. One TLS connection carries all of
// it: an HTTP GET upgraded to "IF-T/TLS 1.0" (the TCG's TNC binding to
// TLS), then IF-T messages back to back. Each has a 16-byte header:
// vendor (24 bits), type, length (header included) and the sender's
// message counter.
//
//  1. Version request and answer (TCG vendor), then a Juniper client-info
//     message.
//  2. The login is EAP inside IF-T "client auth" messages, every payload
//     starting with the auth type 000a4c01. The server's EAP requests are
//     Juniper "expanded" EAP (vendor 0x0a4c, type 1) holding AVPs (RFC 5281
//     style, vendor 0x583 for Juniper's own): realm choices, the session
//     cookie (DSID), and an inner EAP message (AVP 79) for the password
//     (Juniper type 2 or 5) or a one-time code (EAP-GTC).
//  3. "Client auth success", then configuration messages (Juniper type 1:
//     address, netmask, DNS, MTU; and the ESP keys) up to "end of config".
//  4. IP packets are Juniper type 4 messages on the same connection. ESP
//     over UDP is not used: komando answers the ESP key offer (the server
//     waits for it) but keeps every packet on TLS.
//
// The tunnel itself logs in again with the DSID cookie the login gave, so
// the login (which may need a person) and the tunnel are two connections.
// Written from the IF-T/TLS binding and public descriptions of Juniper's
// extensions; no openconnect code. Tested against komando's own fake
// server (pulse_test.go), not yet against an Ivanti appliance.

const (
	pulseVendorTCG = 0x5597
	pulseVendorJNP = 0x0a4c
	pulseAVPVendor = 0x0583

	iftVersionReq  = 1
	iftVersionResp = 2
	iftAuthChal    = 5
	iftAuthResp    = 6
	iftAuthOK      = 7

	jnpConfig     = 0x01
	jnpData       = 0x04
	jnpESPOn      = 0x05
	jnpClientInfo = 0x88
	jnpLogout     = 0x89
	jnpConfigEnd  = 0x8f
	jnpFatal      = 0x93

	pulseAuthType = 0x000a4c01 // "JUNIPER_1"

	eapRequest  = 1
	eapResponse = 2
	eapSuccess  = 3
	eapFailure  = 4
	eapIdentity = 1
	eapGTC      = 6
	eapTTLS     = 21
	eapExpanded = 254

	avpEAPMessage = 79
	avpRealmList  = 0xd4e
	avpRealmEntry = 0xd4f
	avpRealm      = 0xd50
	avpRegionList = 0xd51
	avpRegion     = 0xd52
	avpCookie     = 0xd53
	avpOS         = 0xd5e
	avpFailure    = 0xd60
	avpSessions   = 0xd65
	avpUser       = 0xd6d
	avpVersion    = 0xd70
	avpBanner     = 0xd7b
	avpBannerOK   = 0xd7c
	avpPassLabel  = 0xd81
	avpPass2Label = 0xd83

	j2PassReq    = 0x01
	j2PassRetry  = 0x81
	j2PassChange = 0x43
	j2PassFail   = 0xc5

	pulseClientVersion = "Pulse-Secure/22.2.1.1295 (komando)"
	pulseMaxMsg        = 1 << 20
)

// iftConn reads and writes IF-T messages on the upgraded connection.
type iftConn struct {
	c   net.Conn
	br  *bufio.Reader
	wmu sync.Mutex
	seq uint32
}

type iftMsg struct {
	vendor, typ uint32
	body        []byte // after the 16-byte header
}

func (f *iftConn) send(vendor, typ uint32, body []byte) error {
	b := make([]byte, 16+len(body))
	binary.BigEndian.PutUint32(b[0:], vendor)
	binary.BigEndian.PutUint32(b[4:], typ)
	binary.BigEndian.PutUint32(b[8:], uint32(len(b)))
	copy(b[16:], body)
	f.wmu.Lock()
	defer f.wmu.Unlock()
	binary.BigEndian.PutUint32(b[12:], f.seq)
	f.seq++
	_, err := f.c.Write(b)
	return err
}

func (f *iftConn) read() (iftMsg, error) {
	var h [16]byte
	if _, err := io.ReadFull(f.br, h[:]); err != nil {
		return iftMsg{}, err
	}
	n := binary.BigEndian.Uint32(h[8:])
	if n < 16 || n > pulseMaxMsg {
		return iftMsg{}, fmt.Errorf("the VPN sent a message of %d bytes", n)
	}
	body := make([]byte, n-16)
	if _, err := io.ReadFull(f.br, body); err != nil {
		return iftMsg{}, err
	}
	return iftMsg{vendor: binary.BigEndian.Uint32(h[0:]) & 0xffffff, typ: binary.BigEndian.Uint32(h[4:]), body: body}, nil
}

// pulseAVP is one AVP: code, Juniper vendor or none, data.
type pulseAVP struct {
	code   uint32
	vendor uint32
	data   []byte
}

func parseAVPs(b []byte) ([]pulseAVP, error) {
	var out []pulseAVP
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, errors.New("short AVP")
		}
		a := pulseAVP{code: binary.BigEndian.Uint32(b)}
		flags := b[4]
		l := int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		hdr := 8
		if flags&0x80 != 0 {
			if len(b) < 12 {
				return nil, errors.New("short AVP")
			}
			a.vendor = binary.BigEndian.Uint32(b[8:])
			hdr = 12
		}
		if l < hdr || l > len(b) {
			return nil, errors.New("bad AVP length")
		}
		a.data = b[hdr:l]
		known := a.vendor == pulseAVPVendor || a.vendor == 0 && a.code == avpEAPMessage
		if flags&0x40 != 0 && !known {
			return nil, fmt.Errorf("the VPN requires an attribute komando does not know (%d/%#x)", a.vendor, a.code)
		}
		out = append(out, a)
		pad := (4 - l%4) % 4
		if l+pad > len(b) {
			pad = len(b) - l
		}
		b = b[l+pad:]
	}
	return out, nil
}

func appendAVP(b []byte, code uint32, vendor bool, data []byte) []byte {
	hdr := 8
	flags := byte(0x40) // EAP-Message: mandatory
	if vendor {
		hdr, flags = 12, 0x80
	}
	l := hdr + len(data)
	b = binary.BigEndian.AppendUint32(b, code)
	b = append(b, flags, byte(l>>16), byte(l>>8), byte(l))
	if vendor {
		b = binary.BigEndian.AppendUint32(b, pulseAVPVendor)
	}
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func jnpAVP(b []byte, code uint32, data []byte) []byte { return appendAVP(b, code, true, data) }

// eapPacket builds an EAP packet; typ 0 means none (Success/Failure).
func eapPacket(code, id byte, typ byte, data []byte) []byte {
	b := []byte{code, id, 0, 0}
	if typ != 0 {
		b = append(b, typ)
	}
	b = append(b, data...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

// expanded builds an expanded Juniper EAP packet of vendor type vt.
func expanded(code, id byte, vt uint32, data []byte) []byte {
	p := binary.BigEndian.AppendUint32([]byte{pulseVendorJNP >> 16, pulseVendorJNP >> 8 & 0xff, pulseVendorJNP & 0xff}, vt)
	return eapPacket(code, id, eapExpanded, append(p, data...))
}

// eapMsg is a parsed EAP packet.
type eapMsg struct {
	code, id byte
	typ      byte
	vendorT  uint32 // expanded Juniper vendor type
	data     []byte // after the type (and expanded header)
}

func parseEAP(b []byte) (eapMsg, error) {
	if len(b) < 4 {
		return eapMsg{}, errors.New("short EAP packet")
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n < 4 || n > len(b) {
		return eapMsg{}, errors.New("bad EAP length")
	}
	m := eapMsg{code: b[0], id: b[1]}
	b = b[:n]
	if m.code != eapRequest && m.code != eapResponse {
		return m, nil
	}
	if len(b) < 5 {
		return eapMsg{}, errors.New("EAP packet without a type")
	}
	m.typ, m.data = b[4], b[5:]
	if m.typ == eapExpanded {
		if len(b) < 12 || b[5] != 0 || b[6] != 0x0a || b[7] != 0x4c {
			return eapMsg{}, errors.New("expanded EAP from another vendor")
		}
		m.vendorT, m.data = binary.BigEndian.Uint32(b[8:]), b[12:]
	}
	return m, nil
}

// authBody is an IF-T client-auth payload: the auth type, then EAP.
func authBody(eap []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, pulseAuthType), eap...)
}

// pulseSession is one IF-T connection up to the end of the login.
type pulseSession struct {
	f       *iftConn
	o       Options
	cookie  string // DSID
	resume  bool   // logging in with a cookie: no questions expected
	sentPw  bool
	addrs   []netip.Addr
	dns     []netip.Addr
	mtu     int
	pending []byte // first data packets that came with the configuration
}

// pulseOpen connects, upgrades to IF-T and logs in: with cookie (the
// tunnel) or with the password and o.Prompt (the login).
func pulseOpen(ctx context.Context, o Options, cookie string) (*pulseSession, error) {
	u, err := portalURL(o.Portal)
	if err != nil {
		return nil, err
	}
	c, err := dialTLS(ctx, o, u)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	path := u.EscapedPath()
	req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nUser-Agent: " + pulseClientVersion +
		"\r\nContent-Type: EAP\r\nUpgrade: IF-T/TLS 1.0\r\nContent-Length: 0\r\n"
	if cookie != "" {
		req += "Cookie: DSID=" + cookie + "\r\n"
	}
	if _, err := io.WriteString(c, req+"\r\n"); err != nil {
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, fmt.Errorf("the portal did not answer like Pulse: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("the portal does not speak IF-T/TLS (it answered %s)", resp.Status)
	}
	s := &pulseSession{f: &iftConn{c: c, br: br}, o: o, cookie: cookie, resume: cookie != ""}
	if err := s.login(); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func (s *pulseSession) expect(vendor, typ uint32) (iftMsg, error) {
	m, err := s.f.read()
	switch {
	case err != nil:
		return m, fmt.Errorf("connection to the VPN lost: %w", err)
	case m.vendor == pulseVendorJNP && m.typ == jnpFatal:
		return m, pulseFatal(m.body)
	case m.vendor != vendor || m.typ != typ:
		return m, fmt.Errorf("unexpected Pulse message %#x/%#x", m.vendor, m.typ)
	}
	return m, nil
}

func (s *pulseSession) login() error {
	if err := s.f.send(pulseVendorTCG, iftVersionReq, []byte{0, 1, 2, 2}); err != nil {
		return err
	}
	m, err := s.expect(pulseVendorTCG, iftVersionResp)
	if err != nil {
		return err
	}
	if len(m.body) != 4 || m.body[3] < 1 || m.body[3] > 2 {
		return errors.New("the VPN chose an IF-T version komando does not speak")
	}
	if err := s.f.send(pulseVendorJNP, jnpClientInfo, []byte("clientHostName=komando clientCapabilities={}\n\x00")); err != nil {
		return err
	}
	// the server opens the login with an empty challenge
	if m, err = s.expect(pulseVendorTCG, iftAuthChal); err != nil {
		return err
	}
	if len(m.body) != 4 || binary.BigEndian.Uint32(m.body) != pulseAuthType {
		return errors.New("the VPN started the login in a way komando does not know")
	}
	if err := s.reply(eapPacket(eapResponse, 1, eapIdentity, []byte("anonymous"))); err != nil {
		return err
	}
	first := true
	for round := 0; round < 32; round++ {
		m, err := s.f.read()
		if err != nil {
			return fmt.Errorf("connection to the VPN lost: %w", err)
		}
		switch {
		case m.vendor == pulseVendorJNP && m.typ == jnpFatal:
			return pulseFatal(m.body)
		case m.vendor == pulseVendorTCG && m.typ == iftAuthOK:
			if len(m.body) < 8 || binary.BigEndian.Uint32(m.body) != pulseAuthType || m.body[4] != eapSuccess {
				return errors.New("the VPN sent a broken login result")
			}
			if s.cookie == "" {
				return errors.New("the VPN finished the login without a session cookie")
			}
			return nil
		case m.vendor != pulseVendorTCG || m.typ != iftAuthChal:
			return fmt.Errorf("unexpected Pulse message %#x/%#x during the login", m.vendor, m.typ)
		}
		if len(m.body) < 8 || binary.BigEndian.Uint32(m.body) != pulseAuthType {
			return errors.New("the VPN sent a broken login message")
		}
		e, err := parseEAP(m.body[4:])
		if err != nil {
			return err
		}
		switch {
		case e.code == eapFailure:
			return &LoginError{Msg: "the VPN refused the login"}
		case e.code != eapRequest:
			return errors.New("the VPN sent an EAP answer instead of a question")
		case e.typ == eapTTLS:
			return &LoginError{Msg: "this Pulse server wants a client certificate login (EAP-TTLS), which komando does not support yet"}
		case e.typ != eapExpanded || e.vendorT != 1:
			return fmt.Errorf("the VPN asked for EAP type %d, which komando does not support", e.typ)
		}
		avps, err := parseAVPs(e.data)
		if err != nil {
			return err
		}
		var out []byte
		if first {
			// the first question tells about the server; komando says who it is
			first = false
			out = jnpAVP(out, avpOS, []byte("Linux"))
			out = jnpAVP(out, avpVersion, []byte(pulseClientVersion))
			if s.cookie != "" {
				out = jnpAVP(out, avpCookie, []byte(s.cookie))
			}
			if err := s.reply(expanded(eapResponse, e.id, 1, out)); err != nil {
				return err
			}
			continue
		}
		if out, err = s.answer(avps); err != nil {
			return err
		}
		if err := s.reply(expanded(eapResponse, e.id, 1, out)); err != nil {
			return err
		}
	}
	return &LoginError{Msg: "the Pulse login did not finish"}
}

func (s *pulseSession) reply(eap []byte) error {
	return s.f.send(pulseVendorTCG, iftAuthResp, authBody(eap))
}

// answer builds the AVPs that answer one server question.
func (s *pulseSession) answer(avps []pulseAVP) ([]byte, error) {
	var realms, regions []string
	labels := map[uint32]string{}
	for _, a := range avps {
		if a.vendor != pulseAVPVendor {
			continue
		}
		switch a.code {
		case avpCookie:
			s.cookie = string(a.data)
			return nil, nil // an empty answer ends the login
		case avpFailure:
			code := uint32(0)
			if len(a.data) == 4 {
				code = binary.BigEndian.Uint32(a.data)
			}
			switch code {
			case 0x0d:
				return nil, &LoginError{Msg: "the VPN refused the login: the account is locked"}
			case 0x0e:
				return nil, &LoginError{Msg: "the VPN wants a client certificate, which komando does not support for Pulse yet"}
			}
			return nil, &LoginError{Msg: fmt.Sprintf("the VPN refused the login (code %#x)", code)}
		case avpRealmList:
			realms = append(realms, string(a.data))
		case avpRealmEntry:
			realms = append(realms, "")
		case avpRegionList:
			regions = append(regions, string(a.data))
		case avpSessions:
			return nil, &LoginError{Msg: "the VPN allows no more sessions for this user; end one in the Pulse portal, then run it again"}
		case avpBanner:
			return s.banner(string(a.data))
		case avpPassLabel, avpPass2Label:
			labels[a.code] = string(a.data)
		}
	}
	if s.resume {
		// a tunnel with a cookie is asked anything else: the session is gone
		return nil, &LoginError{Msg: "the VPN did not take the session cookie (the session ended); log in again with `komando vpn up`"}
	}
	switch {
	case len(realms) > 0:
		v, err := s.choose("Realm", realms)
		return jnpAVP(nil, avpRealm, []byte(v)), err
	case len(regions) > 0:
		v, err := s.choose("Region", regions)
		return jnpAVP(nil, avpRegion, []byte(v)), err
	}
	inner := innerEAP(avps)
	if inner == nil {
		return nil, errors.New("the VPN asked something komando does not understand")
	}
	return s.innerAnswer(inner, labels)
}

func innerEAP(avps []pulseAVP) []byte {
	for _, a := range avps {
		if a.vendor == 0 && a.code == avpEAPMessage {
			return a.data
		}
	}
	return nil
}

// innerAnswer answers the inner EAP question: a password (Juniper type 2
// or 5) or a code (GTC).
func (s *pulseSession) innerAnswer(b []byte, labels map[uint32]string) ([]byte, error) {
	e, err := parseEAP(b)
	if err != nil {
		return nil, err
	}
	if e.code != eapRequest {
		return nil, errors.New("the VPN sent an inner EAP answer instead of a question")
	}
	secret := func(label string) (string, error) {
		if !s.sentPw && s.o.Password != "" {
			return s.o.Password, nil
		}
		if s.o.Prompt == nil {
			return "", ErrNeedsPerson
		}
		return s.o.Prompt(label, true)
	}
	var inner []byte
	switch {
	case e.typ == eapGTC:
		if s.o.Prompt == nil {
			return nil, ErrNeedsPerson
		}
		code, err := s.o.Prompt(cmp.Or(strings.TrimSpace(string(e.data)), "One-time code"), false)
		if err != nil {
			return nil, err
		}
		if len(code) > 253 {
			return nil, errors.New("the code is too long")
		}
		inner = eapPacket(eapResponse, e.id, eapGTC, []byte(code))
	case e.typ == eapExpanded && e.vendorT == 2:
		if len(e.data) < 1 {
			return nil, errors.New("the VPN sent an empty password question")
		}
		switch e.data[0] {
		case j2PassReq:
		case j2PassRetry:
			return nil, &LoginError{Msg: "the VPN refused the login (wrong user name or password)"}
		case j2PassChange:
			return nil, &LoginError{Msg: "the VPN says the password has expired; change it in the Pulse portal first"}
		case j2PassFail:
			msg := "the VPN refused the login"
			if t := e.data[1:]; len(t) >= 2 && t[0] == 1 && int(t[1]) >= 2 && int(t[1]) <= len(t) {
				msg += ": " + strings.TrimSpace(string(t[2:t[1]]))
			}
			return nil, &LoginError{Msg: msg}
		default:
			return nil, fmt.Errorf("the VPN asked a password question komando does not know (%#x)", e.data[0])
		}
		label := cmp.Or(labels[avpPassLabel], "Password")
		if s.sentPw {
			label = cmp.Or(labels[avpPass2Label], "Second password")
		}
		pw, err := secret(label)
		if err != nil {
			return nil, err
		}
		if len(pw) > 253 {
			return nil, errors.New("the password is too long for Pulse")
		}
		inner = expanded(eapResponse, e.id, 2, append([]byte{0x02, 0x02, byte(len(pw) + 2)}, pw...))
	case e.typ == eapExpanded && e.vendorT == 5:
		if len(e.data) < 1 || e.data[0] != 0x01 {
			return nil, errors.New("the VPN asked a password question komando does not know")
		}
		pw, err := secret(cmp.Or(labels[avpPassLabel], "Password"))
		if err != nil {
			return nil, err
		}
		field := make([]byte, 18) // a fixed field, as the Pulse client sends it
		copy(field, pw)
		inner = expanded(eapResponse, e.id, 5, append([]byte{0x01}, field...))
	case e.typ == eapExpanded && e.vendorT == 3:
		return nil, &LoginError{Msg: "this Pulse server wants Host Checker, which komando does not support"}
	default:
		return nil, fmt.Errorf("the VPN asked for inner EAP type %d, which komando does not support", e.typ)
	}
	s.sentPw = true
	out := jnpAVP(nil, avpUser, []byte(s.o.User))
	return appendAVP(out, avpEAPMessage, false, inner), nil
}

// pulseFatal reads a "fatal error" message: errorType=N errorString=...
func pulseFatal(b []byte) error {
	text := strings.TrimRight(string(b), "\x00\n ")
	var kind, msg string
	for _, f := range strings.Fields(text) {
		if v, ok := strings.CutPrefix(f, "errorType="); ok {
			kind = v
		}
		if v, ok := strings.CutPrefix(f, "errorString="); ok {
			if d, err := url.QueryUnescape(v); err == nil {
				v = d
			}
			msg = v
		}
	}
	switch kind {
	case "6":
		return errors.New("the VPN ended this session: the same user connected elsewhere")
	case "7":
		return errors.New("the VPN ended the session")
	case "8":
		return errors.New("the VPN ended the session after it was idle")
	}
	return fmt.Errorf("the VPN ended the session: %s", cmp.Or(msg, text))
}

// PulseLogin logs in (asking o.Prompt for what a person must answer) and
// returns the DSID session cookie.
func PulseLogin(ctx context.Context, o Options) (string, error) {
	s, err := pulseOpen(ctx, o, "")
	if err != nil {
		return "", err
	}
	s.f.c.Close() // the tunnel logs in again with the cookie
	return s.cookie, nil
}

type pulseTun struct {
	base
	f *iftConn
}

// PulseTunnel opens the tunnel with a DSID cookie.
func PulseTunnel(ctx context.Context, o Options, cookie string) (Tunnel, error) {
	s, err := pulseOpen(ctx, o, cookie)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { s.f.c.Close() })
	err = s.configure()
	stop()
	if err != nil {
		s.f.c.Close()
		return nil, err
	}
	t := &pulseTun{base: newBase(), f: s.f}
	t.addrs, t.dns, t.mtu = s.addrs, s.dns, s.mtu
	t.closeFn = func() { s.f.c.Close() }
	for _, p := range s.pendingPackets() {
		t.deliver(p)
	}
	go t.read()
	return t, nil
}

// configure reads the configuration up to "end of config".
func (s *pulseSession) configure() error {
	var gotMain bool
	for i := 0; i < 64; i++ {
		m, err := s.f.read()
		if err != nil {
			return fmt.Errorf("connection to the VPN lost: %w", err)
		}
		if m.vendor != pulseVendorJNP {
			continue
		}
		switch m.typ {
		case jnpFatal:
			return pulseFatal(m.body)
		case jnpConfigEnd:
			if !gotMain {
				return errors.New("the VPN sent no configuration")
			}
			return nil
		case jnpData:
			s.pending = appendPacket(s.pending, m.body)
		case jnpConfig:
			kind, err := configKind(m.body)
			if err != nil {
				return err
			}
			switch kind {
			case 0x2c20f000, 0x2e20f000:
				if err := s.mainConfig(m.body, kind); err != nil {
					return err
				}
				gotMain = true
			case 0x21202400:
				if err := s.espConfig(m.body); err != nil {
					return err
				}
			}
		}
	}
	return errors.New("the VPN configuration did not end")
}

// pending packets are kept length-prefixed until the tunnel exists.
func appendPacket(b, p []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(p))), p...)
}

func (s *pulseSession) pendingPackets() [][]byte {
	var out [][]byte
	b := s.pending
	for len(b) >= 4 {
		n := int(binary.BigEndian.Uint32(b))
		if 4+n > len(b) {
			break
		}
		out = append(out, append([]byte(nil), b[4:4+n]...))
		b = b[4+n:]
	}
	return out
}

// Configuration bodies (after the IF-T header): 16 zero bytes, the kind,
// 4 zero bytes, the length less 16, then the kind's own layout.
func configKind(b []byte) (uint32, error) {
	if len(b) < 0x1c || !bytes.Equal(b[:16], make([]byte, 16)) || binary.BigEndian.Uint32(b[0x14:]) != 0 ||
		int(binary.BigEndian.Uint32(b[0x18:])) != len(b) {
		return 0, errors.New("the VPN sent a broken configuration")
	}
	return binary.BigEndian.Uint32(b[0x10:]), nil
}

func (s *pulseSession) mainConfig(body []byte, kind uint32) error {
	b := body[0x1c:]
	bad := errors.New("the VPN sent a configuration komando cannot read")
	if kind == 0x2e20f000 { // newer servers: blocks before the routes, the last flagged 0x2c00
		for {
			if len(b) < 8 {
				return bad
			}
			flag, l := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
			if l < 8 || l > len(b) {
				return bad
			}
			b = b[l:]
			if flag == 0x2c00 {
				break
			}
		}
	}
	// routes: 0x2e00, length (8 + 16 per route), count; komando's stack
	// sends what the person dials, so the routes are only checked
	if len(b) < 8 || binary.BigEndian.Uint16(b) != 0x2e00 {
		return bad
	}
	rl := int(binary.BigEndian.Uint16(b[2:]))
	if rl < 8 || rl > len(b) || (rl-8)%16 != 0 || int(b[4]) != (rl-8)/16 {
		return bad
	}
	b = b[rl:]
	if len(b) < 8 || int(binary.BigEndian.Uint32(b)) != len(b) {
		return bad
	}
	b = b[8:]
	for len(b) > 0 {
		if len(b) < 4 {
			return bad
		}
		typ, l := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if 4+l > len(b) {
			return bad
		}
		v := b[4 : 4+l]
		b = b[4+l:]
		switch {
		case typ == 0x0001 && l == 4:
			s.addrs = append(s.addrs, netip.AddrFrom4([4]byte(v)))
		case typ == 0x0003 && l == 4:
			s.dns = append(s.dns, netip.AddrFrom4([4]byte(v)))
		case typ == 0x0008 && l == 17:
			s.addrs = append(s.addrs, netip.AddrFrom16([16]byte(v[:16])))
		case typ == 0x000a && l == 16:
			s.dns = append(s.dns, netip.AddrFrom16([16]byte(v)))
		case typ == 0x4005 && l == 4:
			if n := int(binary.BigEndian.Uint32(v)); n > 576 && n <= 65535 {
				s.mtu = n
			}
		}
	}
	if len(s.addrs) == 0 || s.mtu == 0 {
		return errors.New("the VPN configuration has no address or MTU")
	}
	return nil
}

// espConfig answers the server's ESP keys with komando's own (random, never
// used), then says it is ready; packets stay on TLS.
func (s *pulseSession) espConfig(body []byte) error {
	if err := espReply(s.f, body); err != nil {
		return err
	}
	return s.f.send(pulseVendorJNP, jnpESPOn, []byte("ncmo=1\n\x00"))
}

// espReply answers ESP keys: komando's SPI and keys, then the server's
// own block (SPI, length, 64 bytes of keys) copied back.
func espReply(f *iftConn, body []byte) error {
	if len(body) < 0x6a-16 || binary.BigEndian.Uint16(body[0x28:]) != 0x40 {
		return errors.New("the VPN sent ESP keys komando cannot read")
	}
	r := make([]byte, 0xc0-16)
	binary.BigEndian.PutUint32(r[0x10:], 0x21202400)
	binary.BigEndian.PutUint32(r[0x18:], uint32(len(r)))
	binary.BigEndian.PutUint32(r[0x1c:], uint32(len(r)-0x1c))
	binary.BigEndian.PutUint32(r[0x20:], 0x01000000)
	mine := r[0x24 : 0x24+0x46]
	rand.Read(mine[:4])
	binary.BigEndian.PutUint16(mine[4:], 0x40)
	rand.Read(mine[6:])
	copy(r[0x24+0x46:], body[0x24:0x24+0x46])
	return f.send(pulseVendorJNP, jnpConfig, r)
}

func (t *pulseTun) WritePacket(p []byte) error { return t.f.send(pulseVendorJNP, jnpData, p) }

func (t *pulseTun) Close() error {
	t.f.send(pulseVendorJNP, jnpLogout, nil)
	t.end(net.ErrClosed)
	return nil
}

func (t *pulseTun) read() {
	for {
		m, err := t.f.read()
		if err != nil {
			t.end(fmt.Errorf("connection to the VPN lost: %w", err))
			return
		}
		if m.vendor != pulseVendorJNP {
			continue
		}
		switch m.typ {
		case jnpData:
			t.deliver(m.body)
		case jnpFatal:
			t.end(pulseFatal(m.body))
			return
		case jnpConfig: // new ESP keys: answered, still unused
			if kind, err := configKind(m.body); err == nil && kind == 0x21202400 {
				if err := espReply(t.f, m.body); err != nil {
					t.end(err)
					return
				}
			}
		}
	}
}
