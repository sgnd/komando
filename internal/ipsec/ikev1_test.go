package ipsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The default IKEv1 offer has no 3DES and no DH group below 14; legacy
// crypto adds them, after every strong suite.
func TestIKEv1OfferStrongByDefault(t *testing.T) {
	for _, s := range p1Offer(false) {
		if s.weak() || s.group < 14 {
			t.Errorf("default phase 1 offer holds %s", s)
		}
	}
	if s := p1Offer(false)[0]; s.hash.name != "SHA256" || s.group != 14 {
		t.Errorf("the strongest suite must come first, got %s", s)
	}
	for _, s := range espOffer(false) {
		if s.c.triple {
			t.Errorf("default ESP offer holds %s", s)
		}
	}
	legacy := p1Offer(true)
	if len(legacy) != len(p1Suites)+len(p1Legacy) {
		t.Fatalf("legacy offer has %d suites", len(legacy))
	}
	seenWeak := false
	for _, s := range legacy {
		if s.weak() {
			seenWeak = true
		} else if seenWeak {
			t.Errorf("%s comes after a weak suite: strong ones go first", s)
		}
	}
	if !seenWeak || !offersESP(espOffer(true), espSuite{tripleDES, integSHA1}) {
		t.Error("legacy crypto must offer 3DES and DH groups 2 and 5")
	}
	if len(p1Suites) == len(p1Offer(true)) {
		t.Error("p1Offer(true) must not change p1Suites")
	}
}

// answerSA is a server's phase 1 answer that chose suite s.
func answerSA(s p1Suite) *v1Payload {
	return &v1Payload{typ: plSA, body: proposal(1, 1, nil, [][]byte{p1Transform(1, s, 1, 3600)})}
}

// A server may only choose a suite komando offered: not a weaker cipher,
// hash or DH group.
func TestAcceptP1OnlyOffered(t *testing.T) {
	k := &ikeV1{o: &Options{}}
	_, offered := p1SA(p1Offer(false), 1, 28800, 0)
	for _, s := range []p1Suite{{aes256, hSHA256, 14}, {aes128, hSHA1, 14}, {aes256, hSHA256, 19}} {
		if err := k.acceptP1(answerSA(s), offered); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if k.life.Seconds() != 3600 {
		t.Errorf("the server's lifetime was not taken: %s", k.life)
	}
	for _, s := range []p1Suite{{tripleDES, hSHA1, 14}, {aes256, hSHA1, 2}, {aes128, hSHA1, 5}, {aes256, hSHA384, 14}, {aes256, hSHA256, 20}} {
		err := k.acceptP1(answerSA(s), offered)
		if err == nil || !strings.Contains(err.Error(), "did not offer") {
			t.Errorf("%s was accepted without being offered (%v)", s, err)
		}
	}
	_, legacy := p1SA(p1Offer(true), 1, 28800, 0)
	if err := k.acceptP1(answerSA(p1Suite{tripleDES, hSHA1, 2}), legacy); err != nil {
		t.Errorf("legacy crypto: 3DES with group 2 was refused: %v", err)
	}
	// aggressive mode offers one DH group: another one is refused
	_, g14 := p1SA(p1Offer(true), 1, 28800, 14)
	if err := k.acceptP1(answerSA(p1Suite{aes256, hSHA1, 2}), g14); err == nil {
		t.Error("aggressive mode: a DH group komando did not send a key for was accepted")
	}
}

// Without legacy crypto, "no proposal chosen" says that the server may
// want old ciphers, as a LegacyCryptoError the caller turns into the
// setting's name. Other errors, and errors with legacy crypto on, stay.
func TestLegacyHint(t *testing.T) {
	refused := notifyError(14)
	var le *LegacyCryptoError
	if err := legacyHint(&Options{}, refused); !errors.As(err, &le) || !strings.Contains(err.Error(), "accepted none") || !strings.Contains(err.Error(), "legacy crypto") {
		t.Errorf("got %v", err)
	}
	if err := legacyHint(&Options{LegacyCrypto: true}, refused); err != refused {
		t.Errorf("with legacy crypto on: %v", err)
	}
	other := notifyError(24)
	if err := legacyHint(&Options{}, other); err != other {
		t.Errorf("an auth error changed: %v", err)
	}
	if legacyHint(&Options{}, nil) != nil {
		t.Error("nil must stay nil")
	}
}

// The ESP suite the server chooses in quick mode must be one komando
// offered too.
func TestOfferedESPv1(t *testing.T) {
	pick := func(s espSuite) chosen {
		b := espTransformV1(1, s, 1, 3600, 0)
		return chosen{tid: b[1], attrs: parseAttrs(b[4:])}
	}
	if s, err := offeredESPv1(pick(espSuite{gcm256, integAlg{}}), espOffer(false)); err != nil || s.c.name != gcm256.name {
		t.Errorf("AES-GCM-256: %v %v", s, err)
	}
	if _, err := offeredESPv1(pick(espSuite{tripleDES, integSHA1}), espOffer(false)); err == nil {
		t.Error("3DES was taken without legacy crypto")
	}
	if _, err := offeredESPv1(pick(espSuite{tripleDES, integSHA1}), espOffer(true)); err != nil {
		t.Errorf("legacy crypto: 3DES refused: %v", err)
	}
}

// v1Pair is komando (a) and a server (b) after phase 1, with the same keys.
func v1Pair(t *testing.T) (a, b *ikeV1) {
	t.Helper()
	s := p1Suite{aes256, hSHA256, 14}
	mk := func() *ikeV1 {
		return &ikeV1{o: &Options{}, suite: s, ivs: map[uint32][]byte{}, lastIn: map[uint32][]byte{},
			lastOut: map[uint32][]byte{}, pending: map[uint32]chan v1msg{}, txn: make(chan v1msg, 8), p1err: make(chan error, 1)}
	}
	a, b = mk(), mk()
	a.ic, a.rc, a.sA, a.sD, a.key, a.p1IV = random(8), random(8), random(32), random(32), random(32), random(16)
	b.ic, b.rc, b.sA, b.sD, b.key, b.p1IV = a.ic, a.rc, a.sA, a.sD, a.key, a.p1IV
	return a, b
}

// A forged encrypted message, which fails its hash, must leave the
// exchange as it was: the real message after it still decrypts and
// checks out. parse used to move the IV on before the hash was checked.
func TestIKEv1ForgedMessageKeepsTheIV(t *testing.T) {
	a, b := v1Pair(t)
	const mid = 0x1234
	real, err := b.protected(exInfo, mid, []v1Payload{{typ: plNotify, body: b.dpdBody(36136, []byte{0, 0, 0, 1})}})
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte{}, real...)
	forged[len(forged)-1] ^= 0xff // the last block: the IV the next message would use
	if m, err := a.parse(forged); err == nil && m != nil && a.verify(*m, nil) {
		t.Fatal("a forged message passed its hash")
	}
	if a.lastIn[mid] != nil || a.ivs[mid] != nil {
		t.Fatal("a forged message changed the exchange's state")
	}
	m, err := a.parse(real)
	if err != nil || m == nil || !a.verify(*m, nil) {
		t.Fatalf("the real message after a forged one: %v", err)
	}
	if a.lastIn[mid] == nil || a.ivs[mid] == nil {
		t.Fatal("the real message was not accepted")
	}
	// constant-time checks still refuse a short hash
	m.ps[0].body = m.ps[0].body[:4]
	if a.verify(*m, nil) {
		t.Fatal("a cut hash passed")
	}
}

// A quick mode answer that is only an error notify ends quick mode only
// with the server's hash: a forged one used to end it at once.
func TestIKEv1QuickModeNotifyNeedsHash(t *testing.T) {
	a, b := v1Pair(t)
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	tr, err := newTransport(context.Background(), srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.end(errors.New("test over"))
	a.t, a.natOA, a.encapT = tr, plNatOA, 4
	refused := []v1Payload{{typ: plNotify, body: []byte{0, 0, 0, 1, 3, 0, 0, 14}}} // NO-PROPOSAL-CHOSEN
	answer := func(signed bool) error {
		done := make(chan error, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() { done <- a.quickOnce(ctx, false) }()
		for {
			a.mu.Lock()
			var mid uint32
			var ch chan v1msg
			for mid, ch = range a.pending {
			}
			a.mu.Unlock()
			if ch != nil {
				ps := refused
				if signed {
					_, rest := encodeChain(refused)
					ps = append([]v1Payload{{typ: plHash, body: b.hash1(mid, rest)}}, refused...)
				}
				first, body := encodeChain(ps)
				parsed, _ := parseChain(first, body)
				ch <- v1msg{exch: exQuick, mid: mid, ps: parsed, enc: true}
				return <-done
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err := answer(false); err == nil || !strings.Contains(err.Error(), "hash is wrong") {
		t.Fatalf("a forged notify: %v", err)
	}
	if err := answer(true); err == nil || !strings.Contains(err.Error(), "accepted none") {
		t.Fatalf("the server's notify: %v", err)
	}
}

// A server named by an IPv6 address, or a session without an IPv4
// address, gets an error or zeros, never a panic in As4.
func TestIPsecNoIPv6Panic(t *testing.T) {
	if _, _, err := resolve(context.Background(), "[2001:db8::1]:500"); err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("an IPv6 server: %v", err)
	}
	if a, _, err := resolve(context.Background(), "::ffff:192.0.2.1"); err != nil || !a.Is4() {
		t.Fatalf("an IPv4-mapped server: %v %v", a, err)
	}
	k := &ikeV1{tun: true, s: &Session{}}
	if ids := k.quickIDs(); len(ids) != 2 {
		t.Fatalf("quick mode IDs without an address: %v", ids)
	}
	k.s.Address = netip.MustParseAddr("2001:db8::2")
	k.quickIDs()
}

// Mode config that gets an answer without the server's hash, or one that
// is not a REPLY or SET, fails: it used to succeed with no address, and
// quick mode then panicked on the zero address.
func TestIKEv1ModeConfigNeedsAVerifiedReply(t *testing.T) {
	a, b := v1Pair(t)
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	tr, err := newTransport(context.Background(), srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.end(errors.New("test over"))
	a.t, a.tun, a.s = tr, true, &Session{}
	answer := func(ps []v1Payload, signed bool) error {
		done := make(chan error, 1)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() { done <- a.modeConfig(ctx) }()
		for {
			a.mu.Lock()
			var mid uint32
			var ch chan v1msg
			for mid, ch = range a.pending {
			}
			a.mu.Unlock()
			if ch != nil {
				if signed {
					_, rest := encodeChain(ps)
					ps = append([]v1Payload{{typ: plHash, body: b.hash1(mid, rest)}}, ps...)
				}
				first, body := encodeChain(ps)
				parsed, _ := parseChain(first, body)
				ch <- v1msg{exch: exTxn, mid: mid, ps: parsed, enc: true}
				return <-done
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	reply := []v1Payload{attrPayload(cfgRep, 1, attrTLV(cfgIP4Addr, []byte{10, 9, 8, 7}))}
	if err := answer(reply, false); err == nil {
		t.Fatal("an unsigned reply was taken")
	}
	if err := answer([]v1Payload{attrPayload(cfgAck, 1, nil)}, true); err == nil {
		t.Fatal("a signed ACK was taken as the configuration")
	}
	if err := a.quickOnce(context.Background(), false); err == nil || !strings.Contains(err.Error(), "no IPv4 address") {
		t.Fatalf("quick mode without an address: %v", err)
	}
	if err := answer(reply, true); err != nil || a.s.Address.String() != "10.9.8.7" {
		t.Fatalf("the signed reply: %v %v", err, a.s.Address)
	}
}
