package ipsec

import (
	"bytes"
	"math/big"
	"testing"
	"time"
)

// The MODP primes are safe primes of the right size (a wrong digit would
// almost surely break that).
func TestMODPPrimes(t *testing.T) {
	for id, bits := range map[uint16]int{2: 1024, 5: 1536, 14: 2048} {
		p := modpPrimes[id]
		q := new(big.Int).Rsh(p, 1)
		if p.BitLen() != bits || !p.ProbablyPrime(20) || !q.ProbablyPrime(20) {
			t.Fatalf("group %d is not a %d-bit safe prime", id, bits)
		}
	}
}

func TestDHAgree(t *testing.T) {
	for _, id := range []uint16{2, 14, 19, 31} {
		a, err := newDH(id)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := newDH(id)
		s1, err := a.Shared(b.Public())
		if err != nil {
			t.Fatal(err)
		}
		s2, _ := b.Shared(a.Public())
		if !bytes.Equal(s1, s2) {
			t.Fatalf("group %d: no agreement", id)
		}
	}
}

func TestESPRoundTripAndReplay(t *testing.T) {
	for _, s := range espOffer(true) {
		k1, k2 := s.split(random(s.keyLen())), s.split(random(s.keyLen()))
		a, err := newESP(s, 1, 2, k1, k2)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := newESP(s, 2, 1, k2, k1)
		for _, n := range []int{0, 1, 15, 16, 17, 1400} {
			p := random(n)
			pkt, err := a.seal(nextIPv4, p)
			if err != nil {
				t.Fatal(err)
			}
			next, got, err := b.open(pkt)
			if err != nil || next != nextIPv4 || !bytes.Equal(got, p) {
				t.Fatalf("%s len %d: %v", s, n, err)
			}
			if _, _, err := b.open(pkt); err != errReplay {
				t.Fatalf("%s: a replay was accepted (%v)", s, err)
			}
			pkt[len(pkt)-1] ^= 1
			if _, _, err := b.open(pkt); err == nil {
				t.Fatalf("%s: a changed packet was accepted", s)
			}
		}
	}
}

// What one side seals as initiator, the other opens as responder.
func TestIKEv2SealOpen(t *testing.T) {
	for _, s := range []ikeSuite{{aes256, integSHA256, hSHA256, 14}, {gcm128, integAlg{}, hSHA384, 19}, {aes128, integSHA1, hSHA1, 2}} {
		a := &ikeV2{spiI: random(8), spiR: random(8), weInit: true, suite: s, frags: map[uint32]*fragSet{}}
		a.derive(random(32), random(32), random(32), a.spiI, a.spiR)
		b := &ikeV2{spiI: a.spiI, spiR: a.spiR, weInit: false, suite: s, frags: map[uint32]*fragSet{},
			skD: a.skD, skAi: a.skAi, skAr: a.skAr, skEi: a.skEi, skEr: a.skEr}
		ps := []v1Payload{{typ: pNonce, body: random(32)}, {typ: pNotify, body: []byte{0, 0, 0x40, 0}}}
		msg, err := a.seal(exInfo2, 7, false, ps)
		if err != nil {
			t.Fatal(err)
		}
		m, err := b.open(msg)
		if err != nil || m.id != 7 || len(m.ps) != 2 || !bytes.Equal(m.ps[0].body, ps[0].body) {
			t.Fatalf("%v: %v", s.enc.name, err)
		}
		msg[40] ^= 1
		if _, err := b.open(msg); err == nil {
			t.Fatalf("%v: a changed message was accepted", s.enc.name)
		}
		// and back: the responder's answer
		msg, _ = b.seal(exInfo2, 7, true, nil)
		if m, err = a.open(msg); err != nil || m.flags&flagResp == 0 {
			t.Fatalf("%v: response: %v", s.enc.name, err)
		}
	}
}

func TestEAPMSCHAPv2(t *testing.T) {
	e := &eapClient{user: "budi", password: "pw"}
	id, err := e.answer(eapPacket(eapRequest, 1, eapIdentity, nil))
	if err != nil || id[4] != eapIdentity || string(id[5:]) != "budi" {
		t.Fatalf("identity: %v %q", err, id)
	}
	// an unknown method gets a NAK asking for MS-CHAPv2
	nak, _ := e.answer(eapPacket(eapRequest, 2, 13, nil))
	if nak[4] != eapNak || nak[5] != eapMSCHAPv2 {
		t.Fatalf("nak %v", nak)
	}
	ch := append([]byte{1, 9, 0, 0, 16}, random(16)...)
	r, err := e.answer(eapPacket(eapRequest, 3, eapMSCHAPv2, ch))
	if err != nil || r[5] != 2 || r[6] != 9 {
		t.Fatalf("challenge response: %v", err)
	}
	if _, err := e.answer(eapPacket(eapRequest, 4, eapMSCHAPv2, append([]byte{3, 9, 0, 0}, "S=0000000000000000000000000000000000000000"...))); err == nil {
		t.Fatal("a wrong server proof was accepted")
	}
	if _, err := e.answer(eapPacket(eapRequest, 4, eapMSCHAPv2, append([]byte{4, 9, 0, 0}, "E=691 R=0 V=3"...))); err == nil {
		t.Fatal("a failure was not reported")
	}
}

func TestParseChainRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{{0, 0, 0, 2}, {0, 0, 0xff, 0xff}, {1, 0, 0, 4}} {
		if _, err := parseChain(plSA, b); err == nil {
			t.Fatalf("%x accepted", b)
		}
	}
}

// After a rekey the server may keep sending on the old SA: komando still
// takes those packets until the server deletes it.
func TestOldInboundSAStaysAfterRekey(t *testing.T) {
	s := &Session{in: map[uint32]*espSA{}, retired: map[uint32]time.Time{}}
	var got [][]byte
	s.deliver = func(_ byte, p []byte) { got = append(got, p) }
	su := espSuites[2]
	k1, k2 := su.split(random(su.keyLen())), su.split(random(su.keyLen()))
	old, _ := newESP(su, 10, 20, k1, k2)
	s.install(old)
	n1, n2 := su.split(random(su.keyLen())), su.split(random(su.keyLen()))
	s.install(func() *espSA { e, _ := newESP(su, 11, 21, n1, n2); return e }())
	peerOld, _ := newESP(su, 20, 10, k2, k1) // the server's end of the old SA
	pkt, _ := peerOld.seal(nextIPv4, []byte("late"))
	s.retired[10] = time.Now().Add(retireAfter)
	s.inbound(pkt)
	if len(got) != 1 || string(got[0]) != "late" {
		t.Fatalf("a packet on the old SA was dropped: %q", got)
	}
	if s.remove(20); s.in[10] != nil {
		t.Fatal("the server's delete did not remove the old SA")
	}
}
