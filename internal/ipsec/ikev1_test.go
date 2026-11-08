package ipsec

import (
	"errors"
	"strings"
	"testing"
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
