package ipsec

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// IKEv2 (RFC 7296): IKE_SA_INIT, IKE_AUTH with a pre-shared key or an EAP
// login checked against the server's certificate, a virtual address from
// the configuration payload, ESP in tunnel mode over UDP, fragments from
// the server (RFC 7383), liveness checks and rekeys the server starts.

const (
	exSAInit    = 34
	exAuth      = 35
	exChild     = 36
	exInfo2     = 37
	flagInit    = 0x08
	flagResp    = 0x20
	pSA         = 33
	pKE         = 34
	pIDi        = 35
	pIDr        = 36
	pCERT       = 37
	pCERTREQ    = 38
	pAUTH       = 39
	pNonce      = 40
	pNotify     = 41
	pDelete     = 42
	pVID        = 43
	pTSi        = 44
	pTSr        = 45
	pSK         = 46
	pCP         = 47
	pEAP        = 48
	pSKF        = 53
	nInvalidKE  = 17
	nAuthFailed = 24
	nNoProposal = 14
	nTSUnacc    = 38
	nInitialCon = 16384
	nNatSrc     = 16388
	nNatDst     = 16389
	nCookie     = 16390
	nRekeySA    = 16393
	nAuthLife   = 16403
	nFragSupp   = 16430
	nSigHash    = 16431
	nFailedCP   = 37
	nIntAddrF   = 36
)

var v2Errors = map[uint16]string{
	4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION", 7: "INVALID_SYNTAX", 9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI",
	14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED",
	35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE", 37: "FAILED_CP_REQUIRED", 38: "TS_UNACCEPTABLE",
	39: "INVALID_SELECTORS", 43: "TEMPORARY_FAILURE", 44: "CHILD_SA_NOT_FOUND",
}

func v2Error(code uint16) error {
	name := v2Errors[code]
	if name == "" {
		name = fmt.Sprintf("error %d", code)
	}
	switch code {
	case nAuthFailed:
		return &AuthError{Msg: "the VPN refused the login (AUTHENTICATION_FAILED): check the pre-shared key or the user name, password and --id"}
	case nNoProposal:
		return errors.New("the server accepted none of komando's proposals (NO_PROPOSAL_CHOSEN): it may want ciphers komando does not speak")
	case nIntAddrF, nFailedCP:
		return errors.New("the server has no address to give (" + name + ")")
	case nTSUnacc:
		return errors.New("the server refused komando's traffic selectors (TS_UNACCEPTABLE): it may only allow split tunnels komando did not ask for")
	}
	return errors.New("the server sent " + name)
}

// Suites.

type ikeSuite struct {
	enc   cipherAlg
	integ integAlg
	prf   hashAlg
	group uint16
}

func transformV2(typ byte, id uint16, keyBits int, last bool) []byte {
	b := []byte{3, 0, 0, 0, typ, 0}
	if last {
		b[0] = 0
	}
	b = binary.BigEndian.AppendUint16(b, id)
	if keyBits > 0 {
		b = append(b, attrTV(14, uint16(keyBits))...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func proposalV2(num, proto byte, spi []byte, ts [][]byte, last bool) []byte {
	for i := range ts {
		if i == len(ts)-1 {
			ts[i][0] = 0
		} else {
			ts[i][0] = 3
		}
	}
	b := []byte{2, 0, 0, 0, num, proto, byte(len(spi)), byte(len(ts))}
	if last {
		b[0] = 0
	}
	b = append(b, spi...)
	for _, t := range ts {
		b = append(b, t...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

const (
	tENCR  = 1
	tPRF   = 2
	tINTEG = 3
	tDH    = 4
	tESN   = 5
)

var v2Groups = []uint16{14, 19, 31, 20, 15, 2}

func prfID(h hashAlg) uint16 {
	return map[string]uint16{"SHA1": 2, "SHA256": 5, "SHA384": 6, "SHA512": 7}[h.name]
}

func integID(i integAlg) uint16 {
	return map[string]uint16{"SHA1": 2, "SHA256": 12, "SHA384": 13, "SHA512": 14}[i.h.name]
}

func groupsWith(first uint16) []uint16 {
	gs := []uint16{first}
	for _, g := range v2Groups {
		if g != first && g != 15 {
			gs = append(gs, g)
		}
	}
	return gs
}

// ikeProposals: AES-CBC with HMAC, then AES-GCM; the DH group komando
// sends a key for comes first.
func ikeProposals(group uint16) []byte {
	var t1, t2 [][]byte
	for _, k := range []int{256, 128} {
		t1 = append(t1, transformV2(tENCR, 12, k, false))
		t2 = append(t2, transformV2(tENCR, 20, k, false))
	}
	for _, h := range []hashAlg{hSHA256, hSHA384, hSHA512, hSHA1} {
		t1 = append(t1, transformV2(tPRF, prfID(h), 0, false))
		t2 = append(t2, transformV2(tPRF, prfID(h), 0, false))
	}
	for _, i := range []integAlg{integSHA256, integSHA384, integSHA512, integSHA1} {
		t1 = append(t1, transformV2(tINTEG, integID(i), 0, false))
	}
	for _, g := range groupsWith(group) {
		t1 = append(t1, transformV2(tDH, g, 0, false))
		t2 = append(t2, transformV2(tDH, g, 0, false))
	}
	return append(proposalV2(1, 1, nil, t1, false), proposalV2(2, 1, nil, t2, true)...)
}

// espProposals: AES-GCM, then AES-CBC with HMAC; group != 0 adds PFS.
func espProposals(spi []byte, group uint16) []byte {
	var t1, t2 [][]byte
	for _, k := range []int{256, 128} {
		t1 = append(t1, transformV2(tENCR, 20, k, false))
		t2 = append(t2, transformV2(tENCR, 12, k, false))
	}
	for _, i := range []integAlg{integSHA256, integSHA1, integSHA384, integSHA512} {
		t2 = append(t2, transformV2(tINTEG, integID(i), 0, false))
	}
	if group != 0 {
		t1 = append(t1, transformV2(tDH, group, 0, false))
		t2 = append(t2, transformV2(tDH, group, 0, false))
	}
	t1 = append(t1, transformV2(tESN, 0, 0, false))
	t2 = append(t2, transformV2(tESN, 0, 0, false))
	return append(proposalV2(1, 3, spi, t1, false), proposalV2(2, 3, spi, t2, true)...)
}

type v2Prop struct {
	num, proto byte
	spi        []byte
	ts         map[byte][][]byte // type -> transforms (id + attrs)
}

func parseProposals(b []byte) []v2Prop {
	var ps []v2Prop
	for len(b) >= 8 {
		n := int(binary.BigEndian.Uint16(b[2:]))
		if n < 8 || n > len(b) {
			break
		}
		p := b[:n]
		spiLen, nt := int(p[6]), int(p[7])
		if 8+spiLen > n {
			break
		}
		prop := v2Prop{num: p[4], proto: p[5], spi: append([]byte{}, p[8:8+spiLen]...), ts: map[byte][][]byte{}}
		t := p[8+spiLen:]
		for i := 0; i < nt && len(t) >= 8; i++ {
			tl := int(binary.BigEndian.Uint16(t[2:]))
			if tl < 8 || tl > len(t) {
				break
			}
			prop.ts[t[4]] = append(prop.ts[t[4]], t[6:tl])
			t = t[tl:]
		}
		ps = append(ps, prop)
		if b[0] == 0 {
			break
		}
		b = b[n:]
	}
	return ps
}

func tid(t []byte) (uint16, int) {
	id := binary.BigEndian.Uint16(t)
	return id, int(attrNum(parseAttrs(t[2:]), 14))
}

func encFrom(id uint16, bits int) (cipherAlg, bool) {
	switch {
	case id == 12 && bits == 128:
		return aes128, true
	case id == 12 && bits == 256:
		return aes256, true
	case id == 20 && bits == 128:
		return gcm128, true
	case id == 20 && bits == 256:
		return gcm256, true
	case id == 3:
		return tripleDES, true
	}
	return cipherAlg{}, false
}

func prfFrom(id uint16) (hashAlg, bool) {
	h, ok := map[uint16]hashAlg{2: hSHA1, 5: hSHA256, 6: hSHA384, 7: hSHA512}[id]
	return h, ok
}

func integFrom(id uint16) (integAlg, bool) {
	i, ok := map[uint16]integAlg{2: integSHA1, 12: integSHA256, 13: integSHA384, 14: integSHA512}[id]
	return i, ok
}

// chosenIKE reads the server's choice for the IKE SA.
func chosenIKE(b []byte) (ikeSuite, error) {
	ps := parseProposals(b)
	if len(ps) != 1 || ps[0].proto != 1 {
		return ikeSuite{}, errors.New("the server's SA payload is not one IKE proposal")
	}
	p := ps[0]
	var s ikeSuite
	var ok bool
	if len(p.ts[tENCR]) != 1 || len(p.ts[tPRF]) != 1 || len(p.ts[tDH]) != 1 {
		return s, errors.New("the server's IKE proposal is incomplete")
	}
	if s.enc, ok = encFrom(tid(p.ts[tENCR][0])); !ok {
		return s, errors.New("the server chose a cipher komando did not offer")
	}
	if s.prf, ok = prfFrom(binary.BigEndian.Uint16(p.ts[tPRF][0])); !ok {
		return s, errors.New("the server chose a PRF komando did not offer")
	}
	if !s.enc.gcm {
		if len(p.ts[tINTEG]) != 1 {
			return s, errors.New("the server's IKE proposal has no integrity algorithm")
		}
		if s.integ, ok = integFrom(binary.BigEndian.Uint16(p.ts[tINTEG][0])); !ok {
			return s, errors.New("the server chose an integrity algorithm komando did not offer")
		}
	}
	s.group = binary.BigEndian.Uint16(p.ts[tDH][0])
	return s, nil
}

// chosenESP reads the server's choice for a CHILD SA.
func chosenESP(b []byte) (espSuite, []byte, error) {
	ps := parseProposals(b)
	if len(ps) != 1 || ps[0].proto != 3 || len(ps[0].spi) != 4 {
		return espSuite{}, nil, errors.New("the server's SA payload is not one ESP proposal")
	}
	p := ps[0]
	var s espSuite
	var ok bool
	if len(p.ts[tENCR]) != 1 {
		return s, nil, errors.New("the server's ESP proposal has no cipher")
	}
	if s.c, ok = encFrom(tid(p.ts[tENCR][0])); !ok {
		return s, nil, errors.New("the server chose an ESP cipher komando did not offer")
	}
	if !s.c.gcm {
		if len(p.ts[tINTEG]) != 1 {
			return s, nil, errors.New("the server's ESP proposal has no integrity algorithm")
		}
		if s.integ, ok = integFrom(binary.BigEndian.Uint16(p.ts[tINTEG][0])); !ok {
			return s, nil, errors.New("the server chose an ESP integrity algorithm komando did not offer")
		}
	}
	if len(p.ts[tESN]) == 1 && binary.BigEndian.Uint16(p.ts[tESN][0]) != 0 {
		return s, nil, errors.New("the server wants extended sequence numbers, which komando did not offer")
	}
	return s, p.spi, nil
}

// pickESP chooses from proposals the server offers (its rekey).
func pickESP(b []byte) (espSuite, *v2Prop, [][]byte, uint16, bool) {
	for _, p := range parseProposals(b) {
		if p.proto != 3 || len(p.spi) != 4 {
			continue
		}
		var s espSuite
		var enc, integ []byte
		for _, t := range p.ts[tENCR] {
			if c, ok := encFrom(tid(t)); ok {
				s.c, enc = c, t
				break
			}
		}
		if enc == nil {
			continue
		}
		if !s.c.gcm {
			for _, t := range p.ts[tINTEG] {
				if i, ok := integFrom(binary.BigEndian.Uint16(t)); ok {
					s.integ, integ = i, t
					break
				}
			}
			if integ == nil {
				continue
			}
		}
		var group uint16
		for _, t := range p.ts[tDH] {
			g := binary.BigEndian.Uint16(t)
			if _, err := newDH(g); err == nil {
				group = g
				break
			}
		}
		if len(p.ts[tDH]) > 0 && group == 0 {
			continue
		}
		var ts [][]byte
		ts = append(ts, transformV2(tENCR, binary.BigEndian.Uint16(enc), s.c.key*8*boolInt(!s.c.triple), false))
		if integ != nil {
			ts = append(ts, transformV2(tINTEG, binary.BigEndian.Uint16(integ), 0, false))
		}
		if group != 0 {
			ts = append(ts, transformV2(tDH, group, 0, false))
		}
		ts = append(ts, transformV2(tESN, 0, 0, false))
		pp := p
		return s, &pp, ts, group, true
	}
	return espSuite{}, nil, nil, 0, false
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// pickIKE chooses from the IKE proposals the server offers (its rekey).
func pickIKE(b []byte) (ikeSuite, *v2Prop, [][]byte, bool) {
	for _, p := range parseProposals(b) {
		if p.proto != 1 || len(p.spi) != 8 {
			continue
		}
		var s ikeSuite
		var ts [][]byte
		for _, t := range p.ts[tENCR] {
			if c, ok := encFrom(tid(t)); ok && !c.triple {
				s.enc = c
				ts = append(ts, transformV2(tENCR, binary.BigEndian.Uint16(t), c.key*8, false))
				break
			}
		}
		for _, t := range p.ts[tPRF] {
			if h, ok := prfFrom(binary.BigEndian.Uint16(t)); ok {
				s.prf = h
				ts = append(ts, transformV2(tPRF, binary.BigEndian.Uint16(t), 0, false))
				break
			}
		}
		if !s.enc.gcm {
			for _, t := range p.ts[tINTEG] {
				if i, ok := integFrom(binary.BigEndian.Uint16(t)); ok {
					s.integ = i
					ts = append(ts, transformV2(tINTEG, binary.BigEndian.Uint16(t), 0, false))
					break
				}
			}
		}
		for _, t := range p.ts[tDH] {
			g := binary.BigEndian.Uint16(t)
			if _, err := newDH(g); err == nil {
				s.group = g
				ts = append(ts, transformV2(tDH, g, 0, false))
				break
			}
		}
		if s.enc.key == 0 || s.prf.new == nil || (!s.enc.gcm && s.integ.h.new == nil) || s.group == 0 {
			continue
		}
		pp := p
		return s, &pp, ts, true
	}
	return ikeSuite{}, nil, nil, false
}

// The IKE SA.

type v2msg struct {
	exch, flags byte
	id          uint32
	ps          []v1Payload
	raw         []byte
}

func (m v2msg) notifies() map[uint16][]byte {
	n := map[uint16][]byte{}
	for _, p := range m.ps {
		if p.typ == pNotify && len(p.body) >= 4 {
			spiLen := int(p.body[1])
			if len(p.body) >= 4+spiLen {
				n[binary.BigEndian.Uint16(p.body[2:])] = p.body[4+spiLen:]
			}
		}
	}
	return n
}

// errorNotify is the first error notification (types below 16384).
func (m v2msg) errorNotify() (uint16, bool) {
	for _, p := range m.ps {
		if p.typ == pNotify && len(p.body) >= 4 {
			if t := binary.BigEndian.Uint16(p.body[2:]); t < 16384 {
				return t, true
			}
		}
	}
	return 0, false
}

type fragSet struct {
	total int
	next  byte
	parts map[int][]byte
}

type ikeV2 struct {
	t *udpTransport
	s *Session
	o *Options
	c *v2Conn

	mu          sync.Mutex
	in          chan []byte
	spiI        []byte
	spiR        []byte
	weInit      bool
	suite       ikeSuite
	skD         []byte
	skAi        []byte
	skAr        []byte
	skEi        []byte
	skEr        []byte
	skPi        []byte
	skPr        []byte
	nextID      uint32
	peerID      uint32
	resps       map[uint32][]byte
	pending     map[uint32]chan v2msg
	frags       map[uint32]*fragSet
	ended       bool
	alive       time.Time // last message from the server
	authLife    time.Duration
	serverID    []byte // the server's ID payload body
	tsi, tsr    []byte // the traffic selectors the server agreed to
	stop        chan struct{}
	authStarted bool
}

func newIKEv2(t *udpTransport, s *Session, o *Options, c *v2Conn) *ikeV2 {
	k := &ikeV2{t: t, s: s, o: o, c: c, spiI: random(8), spiR: make([]byte, 8), weInit: true,
		resps: map[uint32][]byte{}, pending: map[uint32]chan v2msg{}, frags: map[uint32]*fragSet{},
		alive: time.Now(), stop: make(chan struct{})}
	k.in = t.route(k.spiI)
	go k.run()
	return k
}

func (k *ikeV2) header(exch byte, id uint32, response bool, next byte, length int) []byte {
	h := make([]byte, 28)
	copy(h, k.spiI)
	copy(h[8:], k.spiR)
	h[16], h[17], h[18] = next, 0x20, exch
	if k.weInit {
		h[19] |= flagInit
	}
	if response {
		h[19] |= flagResp
	}
	binary.BigEndian.PutUint32(h[20:], id)
	binary.BigEndian.PutUint32(h[24:], uint32(length))
	return h
}

func (k *ikeV2) plain(exch byte, id uint32, ps []v1Payload) []byte {
	first, body := encodeChain(ps)
	return append(k.header(exch, id, false, first, 28+len(body)), body...)
}

// keys for what we send and what we receive
func (k *ikeV2) outKeys() (e, a []byte) {
	if k.weInit {
		return k.skEi, k.skAi
	}
	return k.skEr, k.skAr
}

func (k *ikeV2) inKeys() (e, a []byte) {
	if k.weInit {
		return k.skEr, k.skAr
	}
	return k.skEi, k.skAi
}

// seal builds an encrypted message (SK payload).
func (k *ikeV2) seal(exch byte, id uint32, response bool, ps []v1Payload) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	first, inner := encodeChain(ps)
	ek, ak := k.outKeys()
	s := k.suite
	if s.enc.gcm {
		plain := append(inner, 0)
		iv := random(8)
		skLen := 4 + 8 + len(plain) + 16
		h := k.header(exch, id, response, pSK, 28+skLen)
		skh := []byte{first, 0, 0, 0}
		binary.BigEndian.PutUint16(skh[2:], uint16(skLen))
		aad := append(append([]byte{}, h...), skh...)
		blk, err := s.enc.block(ek[:s.enc.key])
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, err
		}
		ct := g.Seal(nil, append(append([]byte{}, ek[s.enc.key:]...), iv...), plain, aad)
		return append(append(aad, iv...), ct...), nil
	}
	bs := s.enc.blockSize()
	pad := (bs - (len(inner)+1)%bs) % bs
	plain := append(append(inner, make([]byte, pad)...), byte(pad))
	iv := random(bs)
	ct, err := cbcEncrypt(s.enc, ek, iv, plain)
	if err != nil {
		return nil, err
	}
	skLen := 4 + bs + len(ct) + s.integ.icv
	h := k.header(exch, id, response, pSK, 28+skLen)
	skh := []byte{first, 0, 0, 0}
	binary.BigEndian.PutUint16(skh[2:], uint16(skLen))
	msg := append(append(append(h, skh...), iv...), ct...)
	return append(msg, s.integ.mac(ak, msg)...), nil
}

// open checks and decrypts the SK (or SKF) payload of a message. It
// returns nil payloads while fragments are still missing.
func (k *ikeV2) open(raw []byte) (*v2msg, error) {
	if len(raw) < 28 || raw[17] != 0x20 {
		return nil, errors.New("not IKEv2")
	}
	n := int(binary.BigEndian.Uint32(raw[24:]))
	if n > len(raw) || n < 28 {
		return nil, errors.New("bad length")
	}
	raw = raw[:n]
	m := &v2msg{exch: raw[18], flags: raw[19], id: binary.BigEndian.Uint32(raw[20:]), raw: raw}
	next := raw[16]
	if next != pSK && next != pSKF {
		ps, err := parseChain(next, raw[28:])
		m.ps = ps
		return m, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.skD == nil {
		return nil, errors.New("encrypted message before the keys")
	}
	if len(raw) < 32 {
		return nil, errors.New("short SK payload")
	}
	inner := raw[28+4:]
	hdrLen := 28 + 4
	fragNum, fragTotal := 1, 1
	if next == pSKF {
		if len(inner) < 4 {
			return nil, errors.New("short SKF payload")
		}
		fragNum, fragTotal = int(binary.BigEndian.Uint16(inner)), int(binary.BigEndian.Uint16(inner[2:]))
		inner, hdrLen = inner[4:], hdrLen+4
		if fragNum < 1 || fragNum > fragTotal || fragTotal > 64 {
			return nil, errors.New("bad fragment number")
		}
	}
	ek, ak := k.inKeys()
	s := k.suite
	var plain []byte
	if s.enc.gcm {
		if len(inner) < 8+16 {
			return nil, errors.New("short SK payload")
		}
		blk, err := s.enc.block(ek[:s.enc.key])
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, err
		}
		nonce := append(append([]byte{}, ek[s.enc.key:]...), inner[:8]...)
		if plain, err = g.Open(nil, nonce, inner[8:], raw[:hdrLen]); err != nil {
			return nil, errors.New("IKE message failed its integrity check")
		}
	} else {
		bs, icv := s.enc.blockSize(), s.integ.icv
		if len(inner) < bs+bs+icv || (len(inner)-bs-icv)%bs != 0 {
			return nil, errors.New("bad SK payload length")
		}
		if !hmac.Equal(raw[len(raw)-icv:], s.integ.mac(ak, raw[:len(raw)-icv])) {
			return nil, errors.New("IKE message failed its integrity check")
		}
		var err error
		if plain, err = cbcDecrypt(s.enc, ek, inner[:bs], inner[bs:len(inner)-icv]); err != nil {
			return nil, err
		}
	}
	if len(plain) < 1 || int(plain[len(plain)-1])+1 > len(plain) {
		return nil, errors.New("bad padding")
	}
	plain = plain[:len(plain)-1-int(plain[len(plain)-1])]
	first := raw[28]
	if fragTotal > 1 {
		key := m.id
		if m.flags&flagResp == 0 {
			key |= 1 << 31 // requests and responses may share an id
		}
		f := k.frags[key]
		if f == nil || f.total != fragTotal {
			f = &fragSet{total: fragTotal, parts: map[int][]byte{}}
			k.frags[key] = f
		}
		if fragNum == 1 {
			f.next = first
		}
		f.parts[fragNum] = plain
		if len(f.parts) < f.total {
			return nil, nil
		}
		delete(k.frags, key)
		plain = nil
		for i := 1; i <= f.total; i++ {
			plain = append(plain, f.parts[i]...)
		}
		first = f.next
	}
	ps, err := parseChain(first, plain)
	if err != nil {
		return nil, err
	}
	m.ps = ps
	return m, nil
}

func (k *ikeV2) run() {
	for {
		k.mu.Lock()
		in := k.in
		k.mu.Unlock()
		select {
		case <-k.t.done:
			return
		case <-k.stop:
			return
		case raw := <-in:
			k.o.debugf("IKEv2: received %d bytes (exchange %d)", len(raw), raw[18])
			m, err := k.open(raw)
			if err != nil {
				k.o.logf("IKEv2: dropped a message: %v", err)
				continue
			}
			if m == nil {
				continue
			}
			k.mu.Lock()
			k.alive = time.Now()
			k.mu.Unlock()
			if m.flags&flagResp != 0 {
				k.mu.Lock()
				ch := k.pending[m.id]
				k.mu.Unlock()
				if ch != nil {
					select {
					case ch <- *m:
					default:
					}
				}
				continue
			}
			k.request(m)
		}
	}
}

// roundTrip sends a request and waits for its response, sending again
// while none comes.
func (k *ikeV2) roundTrip(ctx context.Context, exch byte, ps []v1Payload, encrypted bool) (v2msg, []byte, error) {
	k.mu.Lock()
	id := k.nextID
	k.nextID++
	ch := make(chan v2msg, 4)
	k.pending[id] = ch
	k.mu.Unlock()
	defer func() {
		k.mu.Lock()
		delete(k.pending, id)
		k.mu.Unlock()
	}()
	var msg []byte
	var err error
	if encrypted {
		if msg, err = k.seal(exch, id, false, ps); err != nil {
			return v2msg{}, nil, err
		}
	} else {
		msg = k.plain(exch, id, ps)
	}
	wait := time.Second
	for try := 0; try < 7; try++ {
		k.o.debugf("IKEv2: sending %d bytes (exchange %d, message %d, try %d) to %s", len(msg), exch, id, try+1, k.t.server)
		if err := k.t.sendIKE(msg); err != nil {
			return v2msg{}, msg, err
		}
		timer := time.NewTimer(wait)
		select {
		case m := <-ch:
			timer.Stop()
			return m, msg, nil
		case <-ctx.Done():
			timer.Stop()
			return v2msg{}, msg, ctx.Err()
		case <-k.t.done:
			timer.Stop()
			return v2msg{}, msg, fmt.Errorf("the connection ended: %v", k.t.err)
		case <-k.stop:
			timer.Stop()
			return v2msg{}, msg, errors.New("the IKE SA ended")
		case <-timer.C:
			wait = min(wait*2, 8*time.Second)
		}
	}
	return v2msg{}, msg, errNoAnswer
}

var errNoAnswer = errors.New("no answer from the server")

// IKE_SA_INIT.

func (k *ikeV2) natNotifies() []v1Payload {
	srv := k.t.server.As4()
	port := binary.BigEndian.AppendUint16(nil, uint16(k.t.port))
	n := func(t uint16, d []byte) v1Payload {
		return v1Payload{typ: pNotify, body: append(binary.BigEndian.AppendUint16([]byte{0, 0}, t), d...)}
	}
	// a made-up source: the server sees a NAT, so ESP goes in UDP
	return []v1Payload{
		n(nNatSrc, hSHA1.sum(k.spiI, k.spiR, random(4), random(2))),
		n(nNatDst, hSHA1.sum(k.spiI, k.spiR, srv[:], port)),
	}
}

func notify(t uint16, data []byte) v1Payload {
	return v1Payload{typ: pNotify, body: append(binary.BigEndian.AppendUint16([]byte{0, 0}, t), data...)}
}

func (k *ikeV2) saInit(ctx context.Context) (msg1, msg2, ni, nr []byte, err error) {
	group := uint16(14)
	var cookie []byte
	for try := 0; try < 4; try++ {
		dh, err := newDH(group)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		ni = random(32)
		var ps []v1Payload
		if cookie != nil {
			ps = append(ps, notify(nCookie, cookie))
		}
		ke := binary.BigEndian.AppendUint16(nil, group)
		ps = append(ps, v1Payload{typ: pSA, body: ikeProposals(group)}, v1Payload{typ: pKE, body: append(append(ke, 0, 0), dh.Public()...)},
			v1Payload{typ: pNonce, body: ni})
		ps = append(ps, k.natNotifies()...)
		ps = append(ps, notify(nFragSupp, nil), notify(nSigHash, []byte{0, 2, 0, 3, 0, 4, 0, 5}))
		k.mu.Lock()
		k.nextID = 0
		k.mu.Unlock()
		r, sent, err := k.roundTrip(ctx, exSAInit, ps, false)
		if err != nil {
			if errors.Is(err, errNoAnswer) {
				return nil, nil, nil, nil, errors.New("the VPN server does not answer on UDP 500 (IKEv2): check the address and that UDP 500 and 4500 are open")
			}
			return nil, nil, nil, nil, err
		}
		ns := r.notifies()
		if c, ok := ns[nCookie]; ok {
			cookie = c
			continue
		}
		if g, ok := ns[nInvalidKE]; ok && len(g) == 2 {
			group = binary.BigEndian.Uint16(g)
			k.o.logf("IKEv2: the server wants DH group %d", group)
			continue
		}
		if code, ok := r.errorNotify(); ok {
			return nil, nil, nil, nil, v2Error(code)
		}
		sa, kep, nrp := find(r.ps, pSA), find(r.ps, pKE), find(r.ps, pNonce)
		if sa == nil || kep == nil || nrp == nil || len(kep.body) < 4 {
			return nil, nil, nil, nil, errors.New("the server's IKE_SA_INIT answer is incomplete")
		}
		s, err := chosenIKE(sa.body)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if s.group != group {
			return nil, nil, nil, nil, errors.New("the server chose another DH group than komando's key")
		}
		gir, err := dh.Shared(kep.body[4:])
		if err != nil {
			return nil, nil, nil, nil, err
		}
		k.mu.Lock()
		copy(k.spiR, r.raw[8:16])
		k.suite = s
		k.derive(s.prf.prf(append(append([]byte{}, ni...), nrp.body...), gir), ni, nrp.body, k.spiI, k.spiR)
		k.mu.Unlock()
		return sent, r.raw, ni, nrp.body, nil
	}
	return nil, nil, nil, nil, errors.New("the server kept asking for another IKE_SA_INIT")
}

// derive computes the IKE SA keys from SKEYSEED (k.mu held).
func (k *ikeV2) derive(skeyseed, ni, nr, spiI, spiR []byte) {
	s := k.suite
	pl := s.prf.size()
	el, al := s.enc.key, s.integ.key
	if s.enc.gcm {
		el, al = s.enc.key+4, 0
	}
	seed := append(append(append(append([]byte{}, ni...), nr...), spiI...), spiR...)
	km := s.prf.prfPlus(skeyseed, seed, pl+2*al+2*el+2*pl)
	k.skD, km = km[:pl], km[pl:]
	k.skAi, km = km[:al], km[al:]
	k.skAr, km = km[:al], km[al:]
	k.skEi, km = km[:el], km[el:]
	k.skEr, km = km[:el], km[el:]
	k.skPi, k.skPr = km[:pl], km[pl:2*pl]
}

// IKE_AUTH.

func idPayload(id string) []byte {
	if a, err := netip.ParseAddr(id); err == nil && a.Is4() {
		b := a.As4()
		return append([]byte{1, 0, 0, 0}, b[:]...)
	}
	t := byte(2) // FQDN
	if strings.Contains(id, "@") {
		t = 3 // RFC 822 address
	}
	return append([]byte{t, 0, 0, 0}, id...)
}

func (k *ikeV2) localID() string {
	if k.o.ID != "" {
		return k.o.ID
	}
	if k.o.User != "" {
		return k.o.User
	}
	return k.t.local().Addr().String()
}

func (k *ikeV2) remoteName() string {
	if k.o.RemoteID != "" {
		return k.o.RemoteID
	}
	h := k.o.Server
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return h
}

func tsAll() []byte {
	return []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}
}

// signedOctets is RealMessage | Nonce | prf(SK_p, ID body) (RFC 7296 2.15).
func (k *ikeV2) signedOctets(msg, nonce, skp, idBody []byte) []byte {
	return append(append(append([]byte{}, msg...), nonce...), k.suite.prf.prf(skp, idBody)...)
}

func (k *ikeV2) authKey(secret []byte, octets []byte) []byte {
	return k.suite.prf.prf(k.suite.prf.prf(secret, []byte("Key Pad for IKEv2")), octets)
}

// childKeys gives the ESP keys of a CHILD SA (initiator->responder first).
func (k *ikeV2) childKeys(s espSuite, gir, ni, nr []byte) (ir, ri espKeys) {
	km := k.suite.prf.prfPlus(k.skD, append(append(append([]byte{}, gir...), ni...), nr...), 2*s.keyLen())
	return s.split(km[:s.keyLen()]), s.split(km[s.keyLen():])
}

func (k *ikeV2) auth(ctx context.Context, msg1, msg2, ni, nr []byte) error {
	k.authStarted = true
	idi := idPayload(k.localID())
	spi := random(4)
	cp := []byte{1, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0} // CFG_REQUEST: INTERNAL_IP4_ADDRESS, INTERNAL_IP4_DNS
	ps := []v1Payload{{typ: pIDi, body: idi}}
	if k.o.RemoteID != "" {
		ps = append(ps, v1Payload{typ: pIDr, body: idPayload(k.o.RemoteID)})
	}
	eap := k.o.User != "" && k.o.PSK == ""
	if !eap {
		octets := k.signedOctets(msg1, nr, k.skPi, idi)
		ps = append(ps, v1Payload{typ: pAUTH, body: append([]byte{authPSK, 0, 0, 0}, k.authKey([]byte(k.o.PSK), octets)...)})
	}
	ps = append(ps, v1Payload{typ: pCP, body: cp}, v1Payload{typ: pSA, body: espProposals(spi, 0)},
		v1Payload{typ: pTSi, body: tsAll()}, v1Payload{typ: pTSr, body: tsAll()}, notify(nInitialCon, nil))
	r, _, err := k.roundTrip(ctx, exAuth, ps, true)
	if err != nil {
		if errors.Is(err, errNoAnswer) {
			return &AuthError{Msg: "the server did not answer the login (IKE_AUTH)"}
		}
		return err
	}
	if code, ok := r.errorNotify(); ok {
		return v2Error(code)
	}
	verifyServer := func(r v2msg, secret []byte) error {
		idr, au := find(r.ps, pIDr), find(r.ps, pAUTH)
		if idr == nil || au == nil || len(au.body) < 4 {
			return errors.New("the server's IKE_AUTH answer has no identity or AUTH")
		}
		k.serverID = append([]byte{}, idr.body...)
		octets := k.signedOctets(msg2, ni, k.skPr, idr.body)
		method, data := au.body[0], au.body[4:]
		if method == authPSK {
			if secret == nil {
				return &AuthError{Msg: "the server proves itself with a pre-shared key, but komando has none for it (add --psk-ref)"}
			}
			if !hmac.Equal(data, k.authKey(secret, octets)) {
				return &AuthError{Msg: "the server's proof is wrong (a wrong pre-shared key, or not the right server)"}
			}
			return nil
		}
		var certs [][]byte
		for _, p := range r.ps {
			if p.typ == pCERT && len(p.body) > 1 && p.body[0] == 4 {
				certs = append(certs, p.body[1:])
			}
		}
		cert, err := verifyServerCert(certs, k.o.CA, k.remoteName())
		if err != nil {
			return &AuthError{Msg: err.Error()}
		}
		if err := verifySignature(cert, method, data, octets); err != nil {
			return &AuthError{Msg: "the server's signature is wrong: " + err.Error()}
		}
		k.o.logf("IKEv2: server certificate %q verified", cert.Subject.CommonName)
		return nil
	}
	if eap {
		if err := verifyServer(r, nil); err != nil {
			return err
		}
		e := &eapClient{user: k.o.User, password: k.o.Password}
		for round := 0; ; round++ {
			ep := find(r.ps, pEAP)
			if ep == nil {
				return errors.New("the server asked for no EAP login")
			}
			if len(ep.body) >= 1 && ep.body[0] == eapSuccess {
				break
			}
			if len(ep.body) >= 1 && ep.body[0] == eapFailure {
				return &AuthError{Msg: "the VPN refused the login (EAP): check the user name and password"}
			}
			if round > 10 {
				return errors.New("the EAP login does not end")
			}
			ans, err := e.answer(ep.body)
			if err != nil {
				return err
			}
			if r, _, err = k.roundTrip(ctx, exAuth, []v1Payload{{typ: pEAP, body: ans}}, true); err != nil {
				return err
			}
			if code, ok := r.errorNotify(); ok {
				return v2Error(code)
			}
		}
		secret := e.msk
		if secret == nil {
			secret = k.skPi
		}
		octets := k.signedOctets(msg1, nr, k.skPi, idi)
		if r, _, err = k.roundTrip(ctx, exAuth, []v1Payload{{typ: pAUTH, body: append([]byte{authPSK, 0, 0, 0}, k.authKey(secret, octets)...)}}, true); err != nil {
			return err
		}
		if code, ok := r.errorNotify(); ok {
			return v2Error(code)
		}
		// the server's AUTH with the EAP key
		au := find(r.ps, pAUTH)
		if au == nil || len(au.body) < 4 {
			return errors.New("the server's last IKE_AUTH answer has no AUTH")
		}
		rsecret := e.msk
		if rsecret == nil {
			rsecret = k.skPr
		}
		idr := k.serverID
		if !hmac.Equal(au.body[4:], k.authKey(rsecret, k.signedOctets(msg2, ni, k.skPr, idr))) {
			return &AuthError{Msg: "the server's proof after the EAP login is wrong"}
		}
	} else if err := verifyServer(r, []byte(k.o.PSK)); err != nil {
		return err
	}
	if t, ok := r.notifies()[nAuthLife]; ok && len(t) == 4 {
		k.authLife = time.Duration(binary.BigEndian.Uint32(t)) * time.Second
	}
	// the virtual address and DNS servers
	if cpp := find(r.ps, pCP); cpp != nil && len(cpp.body) >= 4 {
		for a := cpp.body[4:]; len(a) >= 4; {
			t, n := binary.BigEndian.Uint16(a)&0x7fff, int(binary.BigEndian.Uint16(a[2:]))
			if 4+n > len(a) {
				break
			}
			if n == 4 {
				v := netip.AddrFrom4([4]byte(a[4:8]))
				switch t {
				case 1:
					if !k.s.Address.IsValid() {
						k.s.Address = v
					}
				case 3:
					k.s.DNS = append(k.s.DNS, v)
				}
			}
			a = a[4+n:]
		}
	}
	if !k.s.Address.IsValid() {
		return errors.New("the server gave no address (configuration payload)")
	}
	sa := find(r.ps, pSA)
	if sa == nil {
		return errors.New("the server set up no CHILD SA")
	}
	if p := find(r.ps, pTSi); p != nil {
		k.tsi = append([]byte{}, p.body...)
	}
	if p := find(r.ps, pTSr); p != nil {
		k.tsr = append([]byte{}, p.body...)
	}
	suite, peerSPI, err := chosenESP(sa.body)
	if err != nil {
		return err
	}
	ir, ri := k.childKeys(suite, nil, ni, nr)
	esp, err := newESP(suite, binary.BigEndian.Uint32(spi), binary.BigEndian.Uint32(peerSPI), ri, ir)
	if err != nil {
		return err
	}
	k.s.install(esp)
	k.o.logf("IKEv2: ESP up (%s, SPI %08x/%08x), address %s", suite, esp.spiIn, esp.spiOut, k.s.Address)
	return nil
}
