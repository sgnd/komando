// Package ppp is a minimal PPP peer for the VPNs that carry PPP (L2TP):
// LCP (RFC 1661), IPCP with DNS (RFC 1332, RFC 1877) and the logins the
// server asks for: PAP (RFC 1334), CHAP-MD5 (RFC 1994) and MS-CHAPv2
// (RFC 2759, with the server's proof checked). Compression, encryption
// (MPPE) and IPv6 are never negotiated.
package ppp

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Protocol numbers.
const (
	LCP    = 0xc021
	PAP    = 0xc023
	CHAP   = 0xc223
	IPCP   = 0x8021
	IPV6CP = 0x8057
	CCP    = 0x80fd
	IPv4   = 0x0021
	IPv6   = 0x0057
)

const (
	cfgRequest  = 1
	cfgAck      = 2
	cfgNak      = 3
	cfgReject   = 4
	termRequest = 5
	termAck     = 6
	codeReject  = 7
	protoReject = 8
	echoRequest = 9
	echoReply   = 10
	discardReq  = 11
)

// ErrTimeout: the server stopped answering while the link came up.
var ErrTimeout = quiet

// quiet wraps into messages without changing their text.
var quiet = quietErr{}

type quietErr struct{}

func (quietErr) Error() string { return "" }

// AuthError is a login the server refused.
type AuthError struct{ Msg string }

func (e *AuthError) Error() string { return e.Msg }

// Peer is one PPP link. Send writes a PPP frame (protocol, information).
type Peer struct {
	send     func(proto uint16, data []byte) error
	user     string
	password string

	mu       sync.Mutex
	id       byte
	magic    [4]byte
	mru      uint16
	auth     uint16 // the protocol the server asked to log in with
	chapAlg  byte
	lcpUp    bool
	lcpAcked bool
	authDone bool
	ipcpUp   bool
	ipcpSent bool
	addr     netip.Addr
	dns      []netip.Addr
	ms       *MSCHAPv2
	papTries int
	lastIPCP []byte
	v6Sent   bool
	v6ID     [8]byte
	authSeen bool
	up       chan struct{}
	fail     chan error
	once     sync.Once
	stop     chan struct{}
	// Log, when set, notes the steps of the link (no secrets).
	Log func(format string, args ...any)
}

func (p *Peer) logf(format string, args ...any) {
	if p.Log != nil {
		p.Log(format, args...)
	}
}

// New makes a peer that logs in as user (when the server asks).
func New(send func(uint16, []byte) error, user, password string) *Peer {
	p := &Peer{send: send, user: user, password: password, mru: 1400, up: make(chan struct{}), fail: make(chan error, 1), stop: make(chan struct{})}
	rand.Read(p.magic[:])
	p.addr = netip.IPv4Unspecified()
	return p
}

func (p *Peer) nextID() byte { p.id++; return p.id }

func packet(code, id byte, data []byte) []byte {
	b := make([]byte, 4+len(data))
	b[0], b[1] = code, id
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[4:], data)
	return b
}

func opt(t byte, v []byte) []byte { return append([]byte{t, byte(2 + len(v))}, v...) }

// options walks well-formed options, stopping at a malformed one.
func options(b []byte, fn func(t byte, v []byte, raw []byte)) {
	for len(b) >= 2 && b[1] >= 2 && int(b[1]) <= len(b) {
		fn(b[0], b[2:b[1]], b[:b[1]])
		b = b[b[1]:]
	}
}

// Start sends the first LCP request and sends requests again every
// three seconds until they are answered (RFC 1661 restart timer).
func (p *Peer) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	go p.restart()
	return p.lcpRequest()
}

func (p *Peer) restart() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.up:
			return
		case <-p.stop:
			return
		case <-t.C:
		}
		p.mu.Lock()
		switch {
		case !p.lcpUp:
			p.lcpRequest()
		case p.authDone && p.ipcpSent && !p.ipcpUp && p.lastIPCP != nil:
			p.send(IPCP, p.lastIPCP)
		case !p.authDone && p.auth == PAP && p.lcpAcked:
			p.papRequest()
		}
		p.mu.Unlock()
	}
}

func (p *Peer) lcpRequest() error {
	return p.send(LCP, packet(cfgRequest, p.nextID(), append(opt(1, binary.BigEndian.AppendUint16(nil, p.mru)), opt(5, p.magic[:])...)))
}

func (p *Peer) failWith(err error) error {
	p.once.Do(func() { p.fail <- err; close(p.stop) })
	return err
}

// Handle processes one received control frame. It returns an error when
// the link cannot go on (the server ended it or refused the login).
func (p *Peer) Handle(proto uint16, b []byte) error {
	if len(b) < 4 {
		return nil
	}
	code, id := b[0], b[1]
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n > len(b) || n < 4 {
		return nil
	}
	data := b[4:n]
	p.mu.Lock()
	defer p.mu.Unlock()
	switch proto {
	case LCP:
		return p.lcp(code, id, data)
	case PAP:
		return p.pap(code, data)
	case CHAP:
		return p.chap(code, id, data)
	case IPCP:
		return p.ipcp(code, id, data)
	case IPV6CP:
		return p.ipv6cp(code, id, data)
	case IPv6:
		return nil // komando's tunnels carry IPv4; IPv6 packets are dropped
	default:
		// IPv6, compression and anything else are not spoken
		if p.lcpUp {
			return p.send(LCP, packet(protoReject, p.nextID(), append(binary.BigEndian.AppendUint16(nil, proto), b[:n]...)))
		}
	}
	return nil
}

func (p *Peer) lcp(code, id byte, data []byte) error {
	switch code {
	case cfgRequest:
		var rej, nak []byte
		var auth uint16
		var alg byte
		options(data, func(t byte, v, raw []byte) {
			switch t {
			case 1, 2, 5: // MRU, async control character map, magic number
			case 3: // authentication protocol
				if len(v) < 2 {
					rej = append(rej, raw...)
					return
				}
				switch a := binary.BigEndian.Uint16(v); {
				case a == PAP:
					auth = PAP
				case a == CHAP && len(v) == 3 && (v[2] == 5 || v[2] == 0x81):
					auth, alg = CHAP, v[2]
				default: // CHAP with MD4 (MS-CHAPv1), EAP, ...: ask for MS-CHAPv2
					p.logf("PPP: the server offers login method %x; asking for MS-CHAPv2", v)
					nak = append(nak, opt(3, []byte{0xc2, 0x23, 0x81})...)
				}
			default: // compression of fields, callbacks, multilink, ...
				rej = append(rej, raw...)
			}
		})
		if len(rej) > 0 {
			return p.send(LCP, packet(cfgReject, id, rej))
		}
		if len(nak) > 0 {
			return p.send(LCP, packet(cfgNak, id, nak))
		}
		logIt := !p.authSeen || p.auth != auth || p.chapAlg != alg
		p.auth, p.chapAlg, p.lcpAcked, p.authSeen = auth, alg, true, true
		switch {
		case !logIt:
		case auth == 0:
			p.authDone = true
			p.logf("PPP: the server asks for no login")
		case auth == PAP:
			p.logf("PPP: the server asks to log in with PAP")
		case alg == 0x81:
			p.logf("PPP: the server asks to log in with MS-CHAPv2")
		default:
			p.logf("PPP: the server asks to log in with CHAP-MD5")
		}
		if err := p.send(LCP, packet(cfgAck, id, data)); err != nil {
			return err
		}
	case cfgAck:
		p.lcpUp = true
	case cfgNak:
		options(data, func(t byte, v, _ []byte) {
			if t == 1 && len(v) == 2 {
				if m := binary.BigEndian.Uint16(v); m >= 576 && m <= 1500 {
					p.mru = m
				}
			}
		})
		return p.lcpRequest()
	case cfgReject:
		// fall back to a request with only the magic number
		return p.send(LCP, packet(cfgRequest, p.nextID(), opt(5, p.magic[:])))
	case echoRequest:
		return p.send(LCP, packet(echoReply, id, append(p.magic[:], data[min(4, len(data)):]...)))
	case termRequest:
		p.send(LCP, packet(termAck, id, nil))
		msg := ""
		if c := clean(string(data)); c != "" {
			msg = ": " + c
		}
		if !p.authDone && p.auth != 0 && p.lcpUp {
			return p.failWith(&AuthError{Msg: "the VPN ended the PPP link during the login" + msg + " (often a wrong user name or password)"})
		}
		return p.failWith(errors.New("the VPN ended the PPP link" + msg))
	case echoReply, discardReq, codeReject, protoReject, termAck:
	}
	return p.next()
}

// next moves on once LCP is up in both directions: log in, then IPCP.
func (p *Peer) next() error {
	if !p.lcpUp || !p.lcpAcked {
		return nil
	}
	if !p.authDone {
		if p.auth == PAP && p.papTries == 0 && p.lcpAcked {
			return p.papRequest()
		}
		return nil // CHAP: the server sends the challenge
	}
	if !p.ipcpSent {
		p.ipcpSent = true
		return p.ipcpRequest()
	}
	return nil
}

func (p *Peer) papRequest() error {
	p.papTries++
	if p.papTries > 5 {
		return p.failWith(&AuthError{Msg: "the VPN does not answer the PAP login"})
	}
	d := append([]byte{byte(len(p.user))}, p.user...)
	d = append(append(d, byte(len(p.password))), p.password...)
	return p.send(PAP, packet(1, p.nextID(), d))
}

func (p *Peer) pap(code byte, data []byte) error {
	switch code {
	case 2: // ack
		p.authDone = true
		p.logf("PPP: login accepted (PAP)")
		return p.next()
	case 3: // nak
		return p.failWith(&AuthError{Msg: "the VPN refused the login (PAP)" + pppMessage(data)})
	}
	return nil
}

func pppMessage(data []byte) string {
	if len(data) < 1 || int(data[0]) > len(data)-1 || data[0] == 0 {
		return ""
	}
	return ": " + clean(string(data[1:1+data[0]]))
}

func clean(s string) string {
	b := []rune{}
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && len(b) < 200 {
			b = append(b, r)
		}
	}
	return string(b)
}

func (p *Peer) chap(code, id byte, data []byte) error {
	switch code {
	case 1: // challenge
		if len(data) < 1 || int(data[0]) > len(data)-1 {
			return nil
		}
		ch := data[1 : 1+data[0]]
		var value []byte
		switch p.chapAlg {
		case 0x81:
			var pc [16]byte
			rand.Read(pc[:])
			m, err := NewMSCHAPv2(ch, p.user, p.password, pc)
			if err != nil {
				return p.failWith(err)
			}
			p.ms = m
			value = make([]byte, 0, 49)
			value = append(value, pc[:]...)
			value = append(value, make([]byte, 8)...)
			value = append(value, m.NTResponse[:]...)
			value = append(value, 0) // flags
		default: // MD5
			h := md5.New()
			h.Write([]byte{id})
			h.Write([]byte(p.password))
			h.Write(ch)
			value = h.Sum(nil)
		}
		d := append([]byte{byte(len(value))}, value...)
		return p.send(CHAP, packet(2, id, append(d, p.user...)))
	case 3: // success
		if p.ms != nil {
			if err := p.ms.VerifySuccess(data); err != nil {
				return p.failWith(err)
			}
		}
		p.authDone = true
		p.logf("PPP: login accepted")
		return p.next()
	case 4: // failure
		msg := clean(string(data))
		p.logf("PPP: login refused: %s", msg)
		if p.ms != nil {
			msg = msChapFailure(msg)
		}
		return p.failWith(&AuthError{Msg: "the VPN refused the login" + msg})
	}
	return nil
}

// msChapFailure turns "E=691 R=0 C=... V=3 M=..." into words.
func msChapFailure(s string) string {
	codes := map[string]string{"646": "restricted logon hours", "647": "account disabled", "648": "password expired",
		"649": "no dial-in permission", "691": "wrong user name or password", "709": "the password must be changed"}
	words := ""
	for code, w := range codes {
		if len(s) >= 5 && s[:5] == "E="+code {
			words = w
		}
	}
	if i := strings.Index(s, "M="); i >= 0 && strings.TrimSpace(s[i+2:]) != "" {
		if words != "" {
			words += "; "
		}
		words += "the server says: " + strings.TrimSpace(s[i+2:])
	}
	if words == "" && s != "" {
		words = "the server says: " + s
	}
	if words == "" {
		return ""
	}
	return " (" + words + ")"
}

// ipv6cp completes IPv6 negotiation when the server starts it: some
// servers (MikroTik with IPv6 on) end the link when it is refused. Only
// the interface identifier is spoken; packets stay IPv4.
func (p *Peer) ipv6cp(code, id byte, data []byte) error {
	switch code {
	case cfgRequest:
		var rej []byte
		options(data, func(t byte, v, raw []byte) {
			if t != 1 || len(v) != 8 {
				rej = append(rej, raw...)
			}
		})
		if len(rej) > 0 {
			return p.send(IPV6CP, packet(cfgReject, id, rej))
		}
		if err := p.send(IPV6CP, packet(cfgAck, id, data)); err != nil {
			return err
		}
		if !p.v6Sent {
			p.v6Sent = true
			rand.Read(p.v6ID[:])
			p.v6ID[0] &^= 2 // a local, not universal, identifier
			return p.send(IPV6CP, packet(cfgRequest, p.nextID(), opt(1, p.v6ID[:])))
		}
	case cfgNak:
		options(data, func(t byte, v, _ []byte) {
			if t == 1 && len(v) == 8 {
				copy(p.v6ID[:], v)
			}
		})
		return p.send(IPV6CP, packet(cfgRequest, p.nextID(), opt(1, p.v6ID[:])))
	case termRequest:
		return p.send(IPV6CP, packet(termAck, id, nil))
	}
	return nil
}

func (p *Peer) ipcpRequest() error {
	a := p.addr.As4()
	opts := opt(3, a[:])
	var d1, d2 [4]byte
	if len(p.dns) > 0 {
		d1 = p.dns[0].As4()
	}
	if len(p.dns) > 1 {
		d2 = p.dns[1].As4()
	}
	opts = append(opts, opt(129, d1[:])...)
	opts = append(opts, opt(131, d2[:])...)
	p.lastIPCP = packet(cfgRequest, p.nextID(), opts)
	return p.send(IPCP, p.lastIPCP)
}

func (p *Peer) ipcp(code, id byte, data []byte) error {
	switch code {
	case cfgRequest:
		// the server's own address: accept it; refuse compression
		var rej []byte
		options(data, func(t byte, _, raw []byte) {
			if t != 3 {
				rej = append(rej, raw...)
			}
		})
		if len(rej) > 0 {
			return p.send(IPCP, packet(cfgReject, id, rej))
		}
		return p.send(IPCP, packet(cfgAck, id, data))
	case cfgNak:
		options(data, func(t byte, v, _ []byte) {
			if len(v) != 4 {
				return
			}
			a := netip.AddrFrom4([4]byte(v))
			switch t {
			case 3:
				p.addr = a
			case 129:
				p.dns = setDNS(p.dns, 0, a)
			case 131:
				p.dns = setDNS(p.dns, 1, a)
			}
		})
		return p.ipcpRequest()
	case cfgReject:
		// drop the DNS options the server does not offer
		p.lastIPCP = packet(cfgRequest, p.nextID(), opt(3, p.addr.AsSlice()))
		return p.send(IPCP, p.lastIPCP)
	case cfgAck:
		if p.addr.IsUnspecified() {
			return p.failWith(errors.New("the VPN gave no address (IPCP)"))
		}
		p.ipcpUp = true
		p.once.Do(func() { close(p.up) })
	case termRequest:
		p.send(IPCP, packet(termAck, id, nil))
	}
	return nil
}

func setDNS(d []netip.Addr, i int, v netip.Addr) []netip.Addr {
	for len(d) <= i {
		d = append(d, netip.IPv4Unspecified())
	}
	d[i] = v
	return d
}

// Wait blocks until IPCP is up, the login failed or the time is over.
func (p *Peer) Wait(timeout time.Duration) error {
	select {
	case <-p.up:
		return nil
	case err := <-p.fail:
		return err
	case <-time.After(timeout):
		p.mu.Lock()
		defer p.mu.Unlock()
		switch {
		case !p.lcpUp || !p.lcpAcked:
			return fmt.Errorf("the PPP link did not come up within %s (LCP)%w", timeout, quiet)
		case !p.authDone:
			return fmt.Errorf("the PPP login got no answer within %s%w", timeout, quiet)
		}
		return fmt.Errorf("the VPN gave no address within %s (IPCP)%w", timeout, quiet)
	}
}

// Result is the address and DNS servers the server gave.
func (p *Peer) Result() (netip.Addr, []netip.Addr, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var dns []netip.Addr
	for _, d := range p.dns {
		if d.IsValid() && !d.IsUnspecified() && !slices.Contains(dns, d) {
			dns = append(dns, d)
		}
	}
	return p.addr, dns, int(p.mru)
}

// Terminate tells the server the link ends.
func (p *Peer) Terminate() {
	p.failWith(errors.New("closed"))
	p.mu.Lock()
	defer p.mu.Unlock()
	p.send(LCP, packet(termRequest, p.nextID(), []byte("bye")))
}
