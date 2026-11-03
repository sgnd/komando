package sslvpn

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// A minimal PPP peer (RFC 1661 LCP, RFC 1332 IPCP, RFC 1877 DNS): enough to
// bring up IPv4 over the PPP framing Fortinet and F5 use inside TLS. No
// compression is ever accepted.

const (
	pppLCP    = 0xc021
	pppIPCP   = 0x8021
	pppIPv4   = 0x0021
	pppIPV6CP = 0x8057
	pppCCP    = 0x80fd

	cfgRequest  = 1
	cfgAck      = 2
	cfgNak      = 3
	cfgReject   = 4
	termRequest = 5
	termAck     = 6
	protoReject = 8
	echoRequest = 9
	echoReply   = 10
)

type ppp struct {
	send  func(proto uint16, data []byte) error
	mu    sync.Mutex
	id    byte
	magic [4]byte

	lcpUp, ipcpUp bool
	lcpAcked      bool
	addr          netip.Addr
	dns           []netip.Addr
	up            chan struct{}
	upOnce        sync.Once
	ipcpReq       []byte
}

func newPPP(send func(uint16, []byte) error) *ppp {
	p := &ppp{send: send, up: make(chan struct{})}
	rand.Read(p.magic[:])
	p.addr = netip.IPv4Unspecified()
	return p
}

func (p *ppp) nextID() byte { p.id++; return p.id }

func pkt(code, id byte, opts []byte) []byte {
	b := make([]byte, 4+len(opts))
	b[0], b[1] = code, id
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[4:], opts)
	return b
}

func opt(t byte, v []byte) []byte { return append([]byte{t, byte(2 + len(v))}, v...) }

// start sends the first LCP request.
func (p *ppp) start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.send(pppLCP, pkt(cfgRequest, p.nextID(), append(opt(1, []byte{0x05, 0xdc}), opt(5, p.magic[:])...)))
}

func (p *ppp) ipcpRequest() error {
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
	p.ipcpReq = opts
	return p.send(pppIPCP, pkt(cfgRequest, p.nextID(), opts))
}

// handle processes one control packet; it returns an error when the peer
// ends the link or asks for something komando refuses.
func (p *ppp) handle(proto uint16, b []byte) error {
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
	case pppLCP:
		switch code {
		case cfgRequest:
			// accept MRU, magic, auth none; reject compression options
			var rej []byte
			for o := data; len(o) >= 2 && int(o[1]) <= len(o) && o[1] >= 2; o = o[o[1]:] {
				switch o[0] {
				case 1, 5, 2: // MRU, magic number, async control character map
				case 7, 8: // protocol / address-field compression
					rej = append(rej, o[:o[1]]...)
				default:
					rej = append(rej, o[:o[1]]...)
				}
			}
			if len(rej) > 0 {
				return p.send(pppLCP, pkt(cfgReject, id, rej))
			}
			p.lcpAcked = true
			if err := p.send(pppLCP, pkt(cfgAck, id, data)); err != nil {
				return err
			}
		case cfgAck:
			p.lcpUp = true
		case cfgNak, cfgReject:
			// fall back to a request with only the magic number
			if err := p.send(pppLCP, pkt(cfgRequest, p.nextID(), opt(5, p.magic[:]))); err != nil {
				return err
			}
		case echoRequest:
			return p.send(pppLCP, pkt(echoReply, id, append(p.magic[:], data[min(4, len(data)):]...)))
		case termRequest:
			p.send(pppLCP, pkt(termAck, id, nil))
			return errors.New("the VPN ended the PPP link")
		}
		if p.lcpUp && p.lcpAcked && !p.ipcpUp && p.ipcpReq == nil {
			return p.ipcpRequest()
		}
	case pppIPCP:
		switch code {
		case cfgRequest:
			// the peer's own address: accept it as it comes
			return p.send(pppIPCP, pkt(cfgAck, id, data))
		case cfgNak:
			for o := data; len(o) >= 6 && o[1] == 6; o = o[6:] {
				v, _ := netip.AddrFromSlice(o[2:6])
				switch o[0] {
				case 3:
					p.addr = v
				case 129:
					p.dns = setDNS(p.dns, 0, v)
				case 131:
					p.dns = setDNS(p.dns, 1, v)
				}
			}
			return p.ipcpRequest()
		case cfgReject:
			// drop the DNS options the peer does not offer
			p.ipcpReq = opt(3, p.addr.AsSlice())
			return p.send(pppIPCP, pkt(cfgRequest, p.nextID(), p.ipcpReq))
		case cfgAck:
			p.ipcpUp = true
			p.upOnce.Do(func() { close(p.up) })
		}
	case pppIPV6CP, pppCCP:
		// IPv6 and compression are not negotiated
		return p.send(pppLCP, pkt(protoReject, p.nextID(), append(binary.BigEndian.AppendUint16(nil, proto), b...)))
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

// wait blocks until IPCP is up.
func (p *ppp) wait(timeout time.Duration) error {
	select {
	case <-p.up:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("the PPP link did not come up within %s", timeout)
	}
}

func (p *ppp) result() (netip.Addr, []netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var dns []netip.Addr
	for _, d := range p.dns {
		if d.IsValid() && !d.IsUnspecified() {
			dns = append(dns, d)
		}
	}
	return p.addr, dns
}
