package ipsec

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// What komando offers and accepts in IKEv1: the phase 1 (IKE SA) and ESP
// suites. Only what was offered may be chosen.

// Phase 1 suites.

type p1Suite struct {
	enc   cipherAlg
	hash  hashAlg
	group uint16
}

// p1Suites are what komando offers in phase 1, strongest first: AES with
// SHA-256, then SHA-1 (which servers set up for Windows clients often
// want), and DH group 14 (2048-bit) or 19 (256-bit elliptic curve). The
// list stays short: the first message must fit one UDP packet, because
// many NATs and gateways drop fragmented IKE.
var p1Suites = []p1Suite{
	{aes256, hSHA256, 14}, {aes128, hSHA256, 14}, {aes256, hSHA256, 19}, {aes256, hSHA1, 14}, {aes128, hSHA1, 14},
}

// p1Legacy are offered after p1Suites only when the VPN allows legacy
// crypto (Options.LegacyCrypto): 3DES, a 64-bit block cipher (Sweet32),
// and DH groups 2 (1024-bit) and 5 (1536-bit), small enough for a
// well-funded attacker to break (Logjam). Old servers may offer nothing
// else.
var p1Legacy = []p1Suite{
	{tripleDES, hSHA1, 14}, {aes256, hSHA1, 5}, {aes256, hSHA1, 2}, {aes128, hSHA1, 2}, {tripleDES, hSHA1, 5},
	{tripleDES, hSHA1, 2},
}

// weakGroup reports a DH group only legacy crypto allows.
func weakGroup(g uint16) bool { return g == 2 || g == 5 }

// p1Offer is what this connection offers in phase 1.
func p1Offer(legacy bool) []p1Suite {
	if legacy {
		return append(append([]p1Suite{}, p1Suites...), p1Legacy...)
	}
	return p1Suites
}

func (s p1Suite) String() string {
	return fmt.Sprintf("%s/%s, DH group %d", s.enc.name, s.hash.name, s.group)
}

func (s p1Suite) weak() bool { return s.enc.triple || weakGroup(s.group) }

// offersP1 reports whether s is one of the suites in list.
func offersP1(list []p1Suite, s p1Suite) bool {
	for _, x := range list {
		if x.enc.name == s.enc.name && x.hash.name == s.hash.name && x.group == s.group {
			return true
		}
	}
	return false
}

func hashID(h hashAlg) uint16 {
	return map[string]uint16{"SHA1": 2, "SHA256": 4, "SHA384": 5, "SHA512": 6}[h.name]
}

func p1Transform(n int, s p1Suite, auth uint16, life uint32) []byte {
	b := []byte{byte(n), 1, 0, 0} // KEY_IKE
	if s.enc.triple {
		b = append(b, attrTV(1, 5)...)
	} else {
		b = append(b, attrTV(1, 7)...)
		b = append(b, attrTV(14, uint16(s.enc.key*8))...)
	}
	b = append(b, attrTV(2, hashID(s.hash))...)
	b = append(b, attrTV(3, auth)...)
	b = append(b, attrTV(4, s.group)...)
	b = append(b, attrTV(11, 1)...)
	b = append(b, attrTLV(12, binary.BigEndian.AppendUint32(nil, life))...)
	return b
}

// p1SA is the SA payload body offering suites (one proposal, its
// transforms are alternatives) and the suites it holds. Aggressive mode
// carries one DH group.
func p1SA(suites []p1Suite, auth uint16, life uint32, group uint16) ([]byte, []p1Suite) {
	var ts [][]byte
	var offered []p1Suite
	for _, su := range suites {
		if group != 0 && su.group != group {
			continue
		}
		ts = append(ts, p1Transform(len(ts)+1, su, auth, life))
		offered = append(offered, su)
	}
	return proposal(1, 1, nil, ts), offered
}

// proposal builds an SA payload body: DOI IPsec, situation identity
// only, one proposal of transforms.
func proposal(num, proto byte, spi []byte, transforms [][]byte) []byte {
	var tb []byte
	for i, t := range transforms {
		next := byte(plTrans)
		if i == len(transforms)-1 {
			next = 0
		}
		tb = append(tb, next, 0)
		tb = binary.BigEndian.AppendUint16(tb, uint16(4+len(t)))
		tb = append(tb, t...)
	}
	p := []byte{num, proto, byte(len(spi)), byte(len(transforms))}
	p = append(append(p, spi...), tb...)
	b := []byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 0}
	b = binary.BigEndian.AppendUint16(b, uint16(4+len(p)))
	return append(b, p...)
}

type chosen struct {
	spi   []byte
	tid   byte
	attrs []attr
}

// parseChosen reads the one transform the server picked.
func parseChosen(sa []byte) (chosen, error) {
	if len(sa) < 8+4+4 {
		return chosen{}, errors.New("short SA payload")
	}
	p := sa[8:]
	pl := int(binary.BigEndian.Uint16(p[2:]))
	if pl < 8 || pl > len(p) {
		return chosen{}, errors.New("komando cannot read the server's proposal")
	}
	p = p[4:pl]
	spiLen := int(p[2])
	if len(p) < 4+spiLen+4 {
		return chosen{}, errors.New("komando cannot read the server's proposal")
	}
	c := chosen{spi: append([]byte{}, p[4:4+spiLen]...)}
	t := p[4+spiLen:]
	tl := int(binary.BigEndian.Uint16(t[2:]))
	if tl < 8 || tl > len(t) {
		return chosen{}, errors.New("komando cannot read the server's transform")
	}
	c.tid = t[5]
	c.attrs = parseAttrs(t[8:tl])
	return c, nil
}

func suiteFromP1(as []attr) (p1Suite, error) {
	var s p1Suite
	switch attrNum(as, 1) {
	case 5:
		s.enc = tripleDES
	case 7:
		switch attrNum(as, 14) {
		case 128:
			s.enc = aes128
		case 256:
			s.enc = aes256
		default:
			return s, errors.New("the server chose an AES key length komando does not offer")
		}
	default:
		return s, errors.New("the server chose a cipher komando does not offer")
	}
	switch attrNum(as, 2) {
	case 2:
		s.hash = hSHA1
	case 4:
		s.hash = hSHA256
	case 5:
		s.hash = hSHA384
	case 6:
		s.hash = hSHA512
	default:
		return s, errors.New("the server chose a hash komando does not offer")
	}
	s.group = uint16(attrNum(as, 4))
	return s, nil
}

// ESP suites (phase 2).

var espSuites = []espSuite{
	{gcm256, integAlg{}}, {gcm128, integAlg{}},
	{aes256, integSHA256}, {aes128, integSHA256}, {aes256, integSHA1}, {aes128, integSHA1},
	{aes256, integSHA384}, {aes256, integSHA512},
}

// espLegacy is offered after espSuites only with Options.LegacyCrypto.
var espLegacy = []espSuite{{tripleDES, integSHA1}}

// espOffer is what this connection offers for ESP.
func espOffer(legacy bool) []espSuite {
	if legacy {
		return append(append([]espSuite{}, espSuites...), espLegacy...)
	}
	return espSuites
}

// offersESP reports whether s is one of the suites in list.
func offersESP(list []espSuite, s espSuite) bool {
	for _, x := range list {
		if x.c.name == s.c.name && x.integ.h.name == s.integ.h.name {
			return true
		}
	}
	return false
}

func v1AuthID(i integAlg) uint16 {
	return map[string]uint16{"SHA1": 2, "SHA256": 5, "SHA384": 6, "SHA512": 7}[i.h.name]
}

func espTransformV1(n int, s espSuite, encap uint16, life uint32, group uint16) []byte {
	tid := byte(12)
	switch {
	case s.c.gcm:
		tid = 20
	case s.c.triple:
		tid = 3
	}
	b := []byte{byte(n), tid, 0, 0}
	b = append(b, attrTV(1, 1)...)
	b = append(b, attrTLV(2, binary.BigEndian.AppendUint32(nil, life))...)
	if group != 0 {
		b = append(b, attrTV(3, group)...)
	}
	b = append(b, attrTV(4, encap)...)
	if !s.c.gcm {
		b = append(b, attrTV(5, v1AuthID(s.integ))...)
	}
	if !s.c.triple {
		b = append(b, attrTV(6, uint16(s.c.key*8))...)
	}
	return b
}

// espTransformsV1 are the quick mode transforms for suites.
func espTransformsV1(suites []espSuite, encap uint16, life uint32, group uint16) [][]byte {
	ts := make([][]byte, 0, len(suites))
	for i, s := range suites {
		ts = append(ts, espTransformV1(i+1, s, encap, life, group))
	}
	return ts
}

// offeredESPv1 is the ESP suite the server chose, which must be one of
// offered.
func offeredESPv1(c chosen, offered []espSuite) (espSuite, error) {
	s, err := suiteFromESPv1(c)
	if err == nil && !offersESP(offered, s) {
		err = fmt.Errorf("quick mode: the server chose ESP %s, which komando did not offer", s)
	}
	return s, err
}

func suiteFromESPv1(c chosen) (espSuite, error) {
	var s espSuite
	kl := attrNum(c.attrs, 6)
	switch c.tid {
	case 3:
		s.c = tripleDES
	case 12:
		s.c = map[uint64]cipherAlg{128: aes128, 256: aes256}[kl]
	case 20:
		s.c = map[uint64]cipherAlg{128: gcm128, 256: gcm256}[kl]
	}
	if s.c.key == 0 {
		return s, fmt.Errorf("the server chose ESP transform %d/%d, which komando did not offer", c.tid, kl)
	}
	if !s.c.gcm {
		switch attrNum(c.attrs, 5) {
		case 2:
			s.integ = integSHA1
		case 5:
			s.integ = integSHA256
		case 6:
			s.integ = integSHA384
		case 7:
			s.integ = integSHA512
		default:
			return s, errors.New("the server chose an ESP integrity algorithm komando did not offer")
		}
	}
	return s, nil
}
