package l2tp

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/ppp"
)

type pipe struct {
	out  chan []byte
	in   chan []byte
	done chan struct{}
}

func (p *pipe) Send(b []byte) error   { p.out <- append([]byte{}, b...); return nil }
func (p *pipe) Recv() <-chan []byte   { return p.in }
func (p *pipe) Done() <-chan struct{} { return p.done }

// fakeLNS answers the control exchange like xl2tpd and hands PPP frames
// to a fake PPP server.
func fakeLNS(t *testing.T, p *pipe, chap bool) {
	var ns, nr uint16
	ctrl := func(avps ...[]byte) []byte {
		var body []byte
		for _, a := range avps {
			body = append(body, a...)
		}
		b := u16(0xc802)
		b = append(b, u16(uint16(12+len(body)))...)
		b = append(b, u16(4242)...) // our id as the client's peer... any
		b = append(b, u16(0)...)
		b = append(b, u16(ns)...)
		b = append(b, u16(nr)...)
		ns++
		return append(b, body...)
	}
	pppOut := func(proto uint16, data []byte) []byte {
		b := append(u16(0x0002), u16(1)...)
		b = append(b, u16(1)...)
		b = append(b, 0xff, 0x03)
		b = append(b, u16(proto)...)
		return append(b, data...)
	}
	lcp := func(code, id byte, data []byte) []byte {
		b := []byte{code, id, 0, 0}
		b = append(b, data...)
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		return b
	}
	for b := range p.out {
		flags := binary.BigEndian.Uint16(b)
		if flags&0x8000 != 0 {
			if len(b) <= 12 {
				continue // ZLB
			}
			nr = binary.BigEndian.Uint16(b[8:]) + 1
			as, _ := parseAVPs(b[12:])
			switch binary.BigEndian.Uint16(get(as, avpMsgType)) {
			case tSCCRQ:
				p.in <- ctrl(msgType(tSCCRP), encAVP(avpTunnelID, u16(77)))
			case tICRQ:
				p.in <- ctrl(msgType(tICRP), encAVP(avpSessionID, u16(88)))
			}
			continue
		}
		// data: PPP after flags, tunnel, session and ff 03
		f := b[8:]
		proto, d := binary.BigEndian.Uint16(f), f[2:]
		switch proto {
		case ppp.LCP:
			if d[0] == 1 {
				p.in <- pppOut(ppp.LCP, lcp(2, d[1], d[4:]))
				opts := []byte{5, 6, 1, 2, 3, 4}
				if chap {
					opts = append(opts, 3, 5, 0xc2, 0x23, 5)
				}
				p.in <- pppOut(ppp.LCP, lcp(1, 1, opts))
			} else if d[0] == 2 && chap {
				p.in <- pppOut(ppp.CHAP, lcp(1, 9, append([]byte{4}, "abcd"...)))
			} else if d[0] == 2 {
				p.in <- pppOut(ppp.IPCP, lcp(1, 1, []byte{3, 6, 10, 0, 0, 1}))
			}
		case ppp.CHAP:
			p.in <- pppOut(ppp.CHAP, lcp(3, d[1], nil))
			p.in <- pppOut(ppp.IPCP, lcp(1, 1, []byte{3, 6, 10, 0, 0, 1}))
		case ppp.IPCP:
			if d[0] == 1 && binary.BigEndian.Uint32(d[6:]) == 0 {
				p.in <- pppOut(ppp.IPCP, lcp(3, d[1], []byte{3, 6, 10, 0, 0, 9}))
			} else if d[0] == 1 {
				p.in <- pppOut(ppp.IPCP, lcp(2, d[1], d[4:]))
			}
		case ppp.IPv4:
			p.in <- pppOut(ppp.IPv4, append([]byte{}, d...))
		}
	}
}

func TestDialAgainstFakeLNS(t *testing.T) {
	for _, chap := range []bool{false, true} {
		p := &pipe{out: make(chan []byte, 64), in: make(chan []byte, 64), done: make(chan struct{})}
		go fakeLNS(t, p, chap)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		tun, err := Dial(ctx, p, "budi", "pw", nil)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if tun.Addresses()[0].String() != "10.0.0.9" {
			t.Fatalf("address %v", tun.Addresses())
		}
		tun.WritePacket([]byte{0x45, 1, 2, 3})
		select {
		case pkt := <-tun.Packets():
			if len(pkt) != 4 || pkt[0] != 0x45 {
				t.Fatalf("echo %x", pkt)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no packet back")
		}
		close(p.done)
	}
}

func FuzzHandle(f *testing.F) {
	f.Add([]byte{0xc8, 0x02, 0, 20, 0, 1, 0, 0, 0, 0, 0, 0, 0x80, 8, 0, 0, 0, 0, 0, 2})
	f.Add([]byte{0x00, 0x02, 0, 1, 0, 1, 0xff, 0x03, 0xc0, 0x21, 1, 1, 0, 4})
	f.Fuzz(func(t *testing.T, b []byte) {
		p := &pipe{out: make(chan []byte, 1024), in: make(chan []byte), done: make(chan struct{})}
		tun := &Tunnel{link: p, log: func(string, ...any) {}, unacked: map[uint16][]byte{}, ctrl: make(chan []avp, 16),
			packets: make(chan []byte, 16), done: make(chan struct{})}
		tun.ppp = ppp.New(tun.sendPPP, "u", "p")
		tun.handle(b)
	})
}
