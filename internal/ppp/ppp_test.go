package ppp

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// RFC 2759 section 9.2 test vectors.
func TestMSCHAPv2Vectors(t *testing.T) {
	auth, _ := hex.DecodeString("5B5D7C7D7B3F2F3E3C2C602132262628")
	var peer [16]byte
	pc, _ := hex.DecodeString("21402324255E262A28295F2B3A337C7E")
	copy(peer[:], pc)
	m, err := NewMSCHAPv2(auth, "User", "clientPass", peer)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ToUpper(hex.EncodeToString(m.NTResponse[:])); got != "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF" {
		t.Fatalf("NT response %s", got)
	}
	if got := m.authenticatorResponse(); got != "S=407A5589115FD0D6209F510FE9C04566932CDA56" {
		t.Fatalf("authenticator response %s", got)
	}
	if err := m.VerifySuccess([]byte("S=407A5589115FD0D6209F510FE9C04566932CDA56 M=welcome")); err != nil {
		t.Fatal(err)
	}
	if err := m.VerifySuccess([]byte("S=0000000000000000000000000000000000000000")); err == nil {
		t.Fatal("a wrong server proof was accepted")
	}
	// RFC 3079 3.5.3: the server's send key (Magic3) is the second half
	msk := m.MSK()
	if len(msk) != 32 || strings.ToUpper(hex.EncodeToString(msk[16:])) != "8B7CDC149B993A1BA118CB153F56DCCB" {
		t.Fatalf("MSK %x", msk)
	}
}

// A fake server: LCP with MS-CHAPv2, then IPCP that hands out an address.
func TestPeerLogsInAndGetsAddress(t *testing.T) {
	var peer *Peer
	serverMagic := []byte{9, 9, 9, 9}
	var ms *MSCHAPv2
	auth := []byte("0123456789abcdef")
	frames := make(chan [2]any, 64)
	send := func(proto uint16, b []byte) error { frames <- [2]any{proto, append([]byte{}, b...)}; return nil }
	peer = New(send, "budi", "secret")
	go func() {
		reply := func(proto uint16, b []byte) { peer.Handle(proto, b) }
		reply(LCP, packet(cfgRequest, 1, append(opt(3, []byte{0xc2, 0x23, 0x81}), opt(5, serverMagic)...)))
		for f := range frames {
			proto, b := f[0].(uint16), f[1].([]byte)
			switch proto {
			case LCP:
				if b[0] == cfgRequest {
					reply(LCP, packet(cfgAck, b[1], b[4:]))
					reply(CHAP, packet(1, 7, append([]byte{16}, auth...)))
				}
			case CHAP:
				v := b[5 : 5+49]
				var pc [16]byte
				copy(pc[:], v[:16])
				ms, _ = NewMSCHAPv2(auth, "budi", "secret", pc)
				if string(ms.NTResponse[:]) != string(v[24:48]) {
					reply(CHAP, packet(4, b[1], []byte("E=691 R=0")))
					continue
				}
				reply(CHAP, packet(3, b[1], []byte(ms.authenticatorResponse()+" M=ok")))
			case IPCP:
				if b[0] != cfgRequest {
					continue
				}
				if binary.BigEndian.Uint32(b[6:10]) == 0 {
					nak := append(opt(3, []byte{10, 1, 2, 3}), opt(129, []byte{10, 1, 0, 53})...)
					reply(IPCP, packet(cfgNak, b[1], nak))
				} else {
					reply(IPCP, packet(cfgAck, b[1], b[4:]))
				}
			}
		}
	}()
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	if err := peer.Wait(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	addr, dns, _ := peer.Result()
	if addr.String() != "10.1.2.3" || len(dns) != 1 || dns[0].String() != "10.1.0.53" {
		t.Fatalf("got %v %v", addr, dns)
	}
}

func TestPeerWrongPassword(t *testing.T) {
	var peer *Peer
	frames := make(chan [2]any, 64)
	peer = New(func(proto uint16, b []byte) error { frames <- [2]any{proto, append([]byte{}, b...)}; return nil }, "budi", "nope")
	go func() {
		peer.Handle(LCP, packet(cfgRequest, 1, opt(3, []byte{0xc0, 0x23})))
		for f := range frames {
			proto, b := f[0].(uint16), f[1].([]byte)
			if proto == LCP && b[0] == cfgRequest {
				peer.Handle(LCP, packet(cfgAck, b[1], b[4:]))
			}
			if proto == PAP {
				peer.Handle(PAP, packet(3, b[1], append([]byte{5}, "nope!"...)))
			}
		}
	}()
	peer.Start()
	err := peer.Wait(5 * time.Second)
	if _, ok := err.(*AuthError); !ok {
		t.Fatalf("want an AuthError, got %v", err)
	}
}

// A server that starts IPv6 negotiation gets it completed, not refused.
func TestIPV6CPAnswered(t *testing.T) {
	var sent [][2]any
	p := New(func(proto uint16, b []byte) error {
		sent = append(sent, [2]any{proto, append([]byte{}, b...)})
		return nil
	}, "u", "p")
	if err := p.Handle(IPV6CP, packet(cfgRequest, 5, opt(1, []byte{1, 2, 3, 4, 5, 6, 7, 8}))); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[0][0].(uint16) != IPV6CP || sent[0][1].([]byte)[0] != cfgAck ||
		sent[1][0].(uint16) != IPV6CP || sent[1][1].([]byte)[0] != cfgRequest {
		t.Fatalf("sent %v", sent)
	}
	for _, f := range sent {
		if f[0].(uint16) == LCP {
			t.Fatal("IPV6CP was rejected")
		}
	}
}
