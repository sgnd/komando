// Package l2tp is komando's own L2TP client (RFC 2661): one tunnel with
// one session carrying PPP, which logs in and brings up IPv4. It runs over
// any datagram link; for L2TP/IPsec that is ESP in transport mode
// (internal/ipsec), so nothing on the computer changes.
package l2tp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/ppp"
)

// ErrNoAnswer: the server stopped answering while the session came up
// (often because it still holds an older session of the same user).
var ErrNoAnswer = ppp.ErrTimeout

// Link carries L2TP datagrams (UDP port 1701 to 1701).
type Link interface {
	Send([]byte) error
	Recv() <-chan []byte
	Done() <-chan struct{}
}

const (
	tSCCRQ   = 1
	tSCCRP   = 2
	tSCCCN   = 3
	tStopCCN = 4
	tHELLO   = 6
	tICRQ    = 10
	tICRP    = 11
	tICCN    = 12
	tCDN     = 14

	avpMsgType     = 0
	avpResult      = 1
	avpProtoVer    = 2
	avpFraming     = 3
	avpHostName    = 7
	avpVendor      = 8
	avpTunnelID    = 9
	avpWindow      = 10
	avpChallenge   = 11
	avpSessionID   = 14
	avpCallSerial  = 15
	avpFramingType = 19
	avpTxSpeed     = 24
)

type avp struct {
	t uint16
	v []byte
}

func encAVP(t uint16, v []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, 0x8000|uint16(6+len(v))) // mandatory
	b = append(b, 0, 0)
	b = binary.BigEndian.AppendUint16(b, t)
	return append(b, v...)
}

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func parseAVPs(b []byte) ([]avp, error) {
	var as []avp
	for len(b) >= 6 {
		flags := binary.BigEndian.Uint16(b)
		n := int(flags & 0x3ff)
		if n < 6 || n > len(b) {
			return nil, errors.New("bad AVP length")
		}
		vendor, t := binary.BigEndian.Uint16(b[2:]), binary.BigEndian.Uint16(b[4:])
		if flags&0x4000 != 0 {
			return nil, errors.New("the server hides AVPs with a tunnel secret, which komando does not support")
		}
		if vendor == 0 {
			as = append(as, avp{t, b[6:n]})
		} else if flags&0x8000 != 0 {
			return nil, fmt.Errorf("the server sent a mandatory vendor AVP (%d/%d) komando does not know", vendor, t)
		}
		b = b[n:]
	}
	return as, nil
}

func get(as []avp, t uint16) []byte {
	for _, a := range as {
		if a.t == t {
			return a.v
		}
	}
	return nil
}

// Tunnel is a connected L2TP session: IPv4 packets in and out.
type Tunnel struct {
	link     Link
	log      func(string, ...any)
	mu       sync.Mutex
	ourTID   uint16
	peerTID  uint16
	ourSID   uint16
	peerSID  uint16
	ns, nr   uint16
	unacked  map[uint16][]byte
	ctrl     chan []avp
	ppp      *ppp.Peer
	packets  chan []byte
	done     chan struct{}
	err      error
	once     sync.Once
	addr     netip.Addr
	dns      []netip.Addr
	mtu      int
	lastRecv time.Time
}

// Dial sets up the tunnel and session and logs in with PPP.
func Dial(ctx context.Context, link Link, user, password string, log func(string, ...any)) (*Tunnel, error) {
	if log == nil {
		log = func(string, ...any) {}
	}
	t := &Tunnel{link: link, log: log, ourTID: uint16(1 + time.Now().UnixNano()%65000), ourSID: 1,
		unacked: map[uint16][]byte{}, ctrl: make(chan []avp, 16), packets: make(chan []byte, 256),
		done: make(chan struct{}), lastRecv: time.Now()}
	t.ppp = ppp.New(t.sendPPP, user, password)
	t.ppp.Log = log
	go t.read()
	host, _ := os.Hostname()
	if host == "" {
		host = "komando"
	}
	r, err := t.request(ctx, tSCCRP, msgType(tSCCRQ),
		encAVP(avpProtoVer, []byte{1, 0}), encAVP(avpHostName, []byte(host)), encAVP(avpFraming, u32(3)),
		encAVP(avpTunnelID, u16(t.ourTID)), encAVP(avpWindow, u16(4)), encAVP(avpVendor, []byte("komando")))
	if err != nil {
		t.end(err)
		return nil, err
	}
	if get(r, avpChallenge) != nil {
		err := errors.New("the server asks for an L2TP tunnel secret, which komando does not support (turn off \"challenge\" / tunnel authentication)")
		t.end(err)
		return nil, err
	}
	tid := get(r, avpTunnelID)
	if len(tid) != 2 {
		t.end(errors.New("no tunnel id"))
		return nil, errors.New("the L2TP server gave no tunnel id")
	}
	t.mu.Lock()
	t.peerTID = binary.BigEndian.Uint16(tid)
	t.mu.Unlock()
	if err := t.send(msgType(tSCCCN)); err != nil {
		return nil, err
	}
	r, err = t.request(ctx, tICRP, msgType(tICRQ), encAVP(avpSessionID, u16(t.ourSID)), encAVP(avpCallSerial, u32(1)))
	if err != nil {
		t.Close()
		return nil, err
	}
	sid := get(r, avpSessionID)
	if len(sid) != 2 {
		t.end(errors.New("no session id"))
		return nil, errors.New("the L2TP server gave no session id")
	}
	t.mu.Lock()
	t.peerSID = binary.BigEndian.Uint16(sid)
	t.mu.Unlock()
	if err := t.send(msgType(tICCN), encAVP(avpTxSpeed, u32(100000000)), encAVP(avpFramingType, u32(1))); err != nil {
		t.Close()
		return nil, err
	}
	log("L2TP: tunnel %d/%d, session %d/%d up; PPP next", t.ourTID, t.peerTID, t.ourSID, t.peerSID)
	if err := t.ppp.Start(); err != nil {
		t.Close()
		return nil, err
	}
	if err := t.ppp.Wait(30 * time.Second); err != nil {
		t.Close() // the server must not keep a half-open session (one session per user)
		return nil, err
	}
	t.addr, t.dns, t.mtu = t.ppp.Result()
	log("L2TP: PPP up, address %s, DNS %v", t.addr, t.dns)
	go t.keepalive()
	return t, nil
}

func msgType(t uint16) []byte { return encAVP(avpMsgType, u16(t)) }

// send sends a control message reliably (retransmitted until acked).
func (t *Tunnel) send(avps ...[]byte) error {
	t.mu.Lock()
	var body []byte
	for _, a := range avps {
		body = append(body, a...)
	}
	ns := t.ns
	t.ns++
	pkt := t.ctrlHeader(ns, body)
	t.unacked[ns] = pkt
	t.mu.Unlock()
	go t.retransmit(ns, pkt, msgName(body))
	return t.link.Send(pkt)
}

// ctrlHeader builds a control message (t.mu held).
func (t *Tunnel) ctrlHeader(ns uint16, body []byte) []byte {
	b := u16(0xc802) // T, L, S, version 2
	b = append(b, u16(uint16(12+len(body)))...)
	b = append(b, u16(t.peerTID)...)
	b = append(b, u16(t.peerSIDFor(body))...)
	b = append(b, u16(ns)...)
	b = append(b, u16(t.nr)...)
	return append(b, body...)
}

// peerSIDFor: session messages carry the server's session id; tunnel
// messages carry 0.
func (t *Tunnel) peerSIDFor(body []byte) uint16 {
	if len(body) >= 8 {
		switch binary.BigEndian.Uint16(body[6:]) {
		case tICCN, tCDN:
			return t.peerSID
		}
	}
	return 0
}

func msgName(body []byte) string {
	if len(body) < 8 {
		return "ZLB"
	}
	t := binary.BigEndian.Uint16(body[6:])
	if n, ok := map[uint16]string{tSCCRQ: "SCCRQ", tSCCCN: "SCCCN", tStopCCN: "StopCCN", tHELLO: "HELLO", tICRQ: "ICRQ", tICCN: "ICCN", tCDN: "CDN"}[t]; ok {
		return n
	}
	return fmt.Sprintf("type %d", t)
}

func (t *Tunnel) retransmit(ns uint16, pkt []byte, name string) {
	wait := time.Second
	for try := 0; try < 6; try++ {
		select {
		case <-t.done:
			return
		case <-time.After(wait):
		}
		t.mu.Lock()
		_, pending := t.unacked[ns]
		t.mu.Unlock()
		if !pending {
			return
		}
		t.log("L2TP: no acknowledgement for %s (Ns %d) yet; sending it again", name, ns)
		t.link.Send(pkt)
		wait = min(wait*2, 8*time.Second)
	}
	t.mu.Lock()
	quiet := time.Since(t.lastRecv).Round(time.Second)
	t.mu.Unlock()
	err := fmt.Errorf("the L2TP server stopped acknowledging (%s, Ns %d; nothing received from it for %s)", name, ns, quiet)
	t.log("L2TP: %v", err)
	t.end(err)
}

// request sends a control message and waits for the answer of type want.
func (t *Tunnel) request(ctx context.Context, want uint16, avps ...[]byte) ([]avp, error) {
	if err := t.send(avps...); err != nil {
		return nil, err
	}
	deadline := time.After(20 * time.Second)
	for {
		select {
		case as := <-t.ctrl:
			mt := get(as, avpMsgType)
			if len(mt) != 2 {
				continue
			}
			switch binary.BigEndian.Uint16(mt) {
			case want:
				return as, nil
			case tStopCCN, tCDN:
				return nil, fmt.Errorf("the L2TP server refused%s", result(as))
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.done:
			return nil, t.err
		case <-deadline:
			return nil, fmt.Errorf("the L2TP server does not answer (is xl2tpd or the L2TP service running behind IPsec?)%w", ErrNoAnswer)
		}
	}
}

func result(as []avp) string {
	r := get(as, avpResult)
	if len(r) < 2 {
		return ""
	}
	s := fmt.Sprintf(" (result %d", binary.BigEndian.Uint16(r))
	if len(r) > 4 {
		msg := []rune{}
		for _, c := range string(r[4:]) {
			if c >= 0x20 && c != 0x7f && len(msg) < 120 {
				msg = append(msg, c)
			}
		}
		s += ": " + string(msg)
	}
	return s + ")"
}

func (t *Tunnel) ack() {
	t.mu.Lock()
	pkt := t.ctrlHeader(t.ns, nil) // a ZLB carries the next Ns without using it
	t.mu.Unlock()
	t.link.Send(pkt)
}

func (t *Tunnel) read() {
	for {
		select {
		case <-t.done:
			return
		case <-t.link.Done():
			t.end(errors.New("the IPsec link ended"))
			return
		case b := <-t.link.Recv():
			t.handle(b)
		}
	}
}

func (t *Tunnel) handle(b []byte) {
	if len(b) < 6 {
		return
	}
	flags := binary.BigEndian.Uint16(b)
	if flags&0x000f != 2 {
		return
	}
	p := b[2:]
	if flags&0x4000 != 0 { // length
		if len(p) < 2 {
			return
		}
		n := int(binary.BigEndian.Uint16(p))
		if n > len(b) || n < 6 {
			return
		}
		p = b[4:n]
	}
	if len(p) < 4 {
		return
	}
	p = p[4:] // tunnel id, session id
	var ns, nr uint16
	if flags&0x0800 != 0 {
		if len(p) < 4 {
			return
		}
		ns, nr = binary.BigEndian.Uint16(p), binary.BigEndian.Uint16(p[2:])
		p = p[4:]
	}
	if flags&0x0200 != 0 { // offset
		if len(p) < 2 || int(binary.BigEndian.Uint16(p))+2 > len(p) {
			return
		}
		p = p[2+binary.BigEndian.Uint16(p):]
	}
	t.mu.Lock()
	t.lastRecv = time.Now()
	t.mu.Unlock()
	if flags&0x8000 == 0 {
		t.data(p)
		return
	}
	// control: nr acknowledges everything before it
	t.mu.Lock()
	for k := range t.unacked {
		if int16(nr-k) > 0 {
			delete(t.unacked, k)
		}
	}
	if len(p) == 0 { // ZLB
		t.mu.Unlock()
		return
	}
	if ns != t.nr {
		t.mu.Unlock()
		if int16(ns-t.nr) < 0 {
			t.ack() // a retransmission: acknowledge again
		}
		return
	}
	t.nr++
	t.mu.Unlock()
	as, err := parseAVPs(p)
	if err != nil {
		t.end(err)
		return
	}
	mt := get(as, avpMsgType)
	if len(mt) != 2 {
		return
	}
	switch binary.BigEndian.Uint16(mt) {
	case tStopCCN, tCDN:
		t.ack()
		t.end(fmt.Errorf("the L2TP server ended the session%s", result(as)))
		return
	case tHELLO:
		t.ack()
		return // the server's keepalive; data already counts as alive
	case tSCCRP, tICRP:
		// answered by our next message (SCCCN, ICCN), which acknowledges it
	default:
		t.ack()
	}
	select {
	case t.ctrl <- as:
	default:
	}
}

func (t *Tunnel) data(p []byte) {
	if len(p) >= 2 && p[0] == 0xff && p[1] == 0x03 {
		p = p[2:]
	}
	if len(p) < 2 {
		return
	}
	var proto uint16
	if p[0]&1 == 1 { // compressed protocol field
		proto, p = uint16(p[0]), p[1:]
	} else {
		proto, p = binary.BigEndian.Uint16(p), p[2:]
	}
	if proto == ppp.IPv4 {
		select {
		case t.packets <- append([]byte{}, p...):
		default:
		}
		return
	}
	if err := t.ppp.Handle(proto, p); err != nil {
		t.end(err)
	}
}

func (t *Tunnel) sendPPP(proto uint16, data []byte) error {
	t.mu.Lock()
	h := append(u16(0x0002), u16(t.peerTID)...)
	h = append(h, u16(t.peerSID)...)
	t.mu.Unlock()
	h = append(h, 0xff, 0x03)
	h = append(h, u16(proto)...)
	return t.link.Send(append(h, data...))
}

// keepalive sends a HELLO after a minute without traffic from the server
// (RFC 2661 6.5), so a dead tunnel is noticed.
func (t *Tunnel) keepalive() {
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
			t.mu.Lock()
			idle := time.Since(t.lastRecv)
			t.mu.Unlock()
			if idle > 60*time.Second {
				t.log("L2TP: nothing from the server for %s; sending HELLO", idle.Round(time.Second))
				t.send(msgType(tHELLO))
			}
		}
	}
}

func (t *Tunnel) end(err error) {
	t.once.Do(func() {
		t.err = err
		close(t.done)
	})
}

// WritePacket sends one IPv4 packet.
func (t *Tunnel) WritePacket(p []byte) error { return t.sendPPP(ppp.IPv4, p) }

// Packets are the IPv4 packets from the server.
func (t *Tunnel) Packets() <-chan []byte { return t.packets }

// Done is closed when the tunnel ended.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Err says why it ended.
func (t *Tunnel) Err() error { return t.err }

// Addresses is the address PPP got.
func (t *Tunnel) Addresses() []netip.Addr { return []netip.Addr{t.addr} }

// DNS are the DNS servers PPP got.
func (t *Tunnel) DNS() []netip.Addr { return t.dns }

// MTU of the tunnel.
func (t *Tunnel) MTU() int { return min(t.mtu, 1400) }

// Close ends the PPP link, the session and the tunnel.
func (t *Tunnel) Close() error {
	select {
	case <-t.done:
		return nil
	default:
	}
	t.ppp.Terminate()
	t.send(msgType(tCDN), encAVP(avpResult, []byte{0, 3}), encAVP(avpSessionID, u16(t.ourSID)))
	t.send(msgType(tStopCCN), encAVP(avpResult, []byte{0, 1}), encAVP(avpTunnelID, u16(t.ourTID)))
	time.Sleep(100 * time.Millisecond)
	t.end(errors.New("closed"))
	return nil
}
