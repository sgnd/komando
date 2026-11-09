package ipsec

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// IKEv1 (RFC 2408, 2409) with pre-shared keys: Main Mode for L2TP/IPsec,
// Aggressive Mode with a group name for Cisco-style IPsec, XAUTH and Mode
// Config (draft-beaulieu-ike-xauth-02, draft-dukes-ike-mode-cfg-02), Quick
// Mode for ESP, NAT traversal (RFC 3947) and dead peer detection (RFC 3706).

// exchange types
const (
	exMain   = 2
	exAggr   = 4
	exInfo   = 5
	exTxn    = 6
	exQuick  = 32
	flagEnc  = 1
	v1HdrLen = 28
)

// payload types
const (
	plSA     = 1
	plProp   = 2
	plTrans  = 3
	plKE     = 4
	plID     = 5
	plHash   = 8
	plNonce  = 10
	plNotify = 11
	plDelete = 12
	plVID    = 13
	plAttr   = 14
	plNatD   = 20
	plNatOA  = 21
	plNatDd  = 130 // the draft numbers
	plNatOAd = 131
)

// ID types
const (
	idIPv4       = 1
	idFQDN       = 2
	idUserFQDN   = 3
	idIPv4Subnet = 4
	idKeyID      = 11
)

func md5VID(s string, tail ...byte) []byte {
	h := md5.Sum([]byte(s))
	return append(h[:len(h)-len(tail)], tail...)
}

var (
	vidRFC3947  = md5VID("RFC 3947")
	vidDraft02  = md5VID("draft-ietf-ipsec-nat-t-ike-02")
	vidDraft02n = md5VID("draft-ietf-ipsec-nat-t-ike-02\n")
	vidDraft03  = md5VID("draft-ietf-ipsec-nat-t-ike-03")
	vidDPD      = []byte{0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00}
	vidXAUTH    = []byte{0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12}
	vidUnity    = md5VID("CISCO-UNITY", 1, 0)
)

type v1Payload struct {
	typ  byte
	body []byte
	raw  []byte // with its generic header, as received
}

func encodeChain(ps []v1Payload) (first byte, b []byte) {
	for i, p := range ps {
		next := byte(0)
		if i+1 < len(ps) {
			next = ps[i+1].typ
		}
		b = append(b, next, 0)
		b = binary.BigEndian.AppendUint16(b, uint16(4+len(p.body)))
		b = append(b, p.body...)
	}
	if len(ps) > 0 {
		first = ps[0].typ
	}
	return first, b
}

func parseChain(first byte, b []byte) ([]v1Payload, error) {
	var ps []v1Payload
	for t := first; t != 0; {
		if len(b) < 4 {
			return nil, errors.New("truncated payload")
		}
		n := int(binary.BigEndian.Uint16(b[2:]))
		if n < 4 || n > len(b) {
			return nil, errors.New("bad payload length")
		}
		ps = append(ps, v1Payload{typ: t, body: b[4:n], raw: b[:n]})
		t, b = b[0], b[n:]
		if len(ps) > 64 {
			return nil, errors.New("too many payloads")
		}
	}
	return ps, nil
}

func find(ps []v1Payload, typ byte) *v1Payload {
	for i := range ps {
		if ps[i].typ == typ {
			return &ps[i]
		}
	}
	return nil
}

// Attributes (TV and TLV).

func attrTV(t, v uint16) []byte {
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, 0x8000|t), v)
}

func attrTLV(t uint16, v []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, t)
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

type attr struct {
	t uint16
	v []byte
}

func (a attr) num() uint64 {
	var n uint64
	for _, c := range a.v {
		n = n<<8 | uint64(c)
	}
	return n
}

func parseAttrs(b []byte) []attr {
	var as []attr
	for len(b) >= 4 {
		t := binary.BigEndian.Uint16(b)
		if t&0x8000 != 0 {
			as = append(as, attr{t & 0x7fff, b[2:4]})
			b = b[4:]
			continue
		}
		n := int(binary.BigEndian.Uint16(b[2:]))
		if 4+n > len(b) {
			break
		}
		as = append(as, attr{t, b[4 : 4+n]})
		b = b[4+n:]
	}
	return as
}

func attrNum(as []attr, t uint16) uint64 {
	for _, a := range as {
		if a.t == t {
			return a.num()
		}
	}
	return 0
}

// Notifications.

var v1Notify = map[uint16]string{
	1: "INVALID-PAYLOAD-TYPE", 7: "INVALID-HASH-INFORMATION", 9: "INVALID-SPI", 13: "INVALID-PROPOSAL", 14: "NO-PROPOSAL-CHOSEN",
	16: "PAYLOAD-MALFORMED", 18: "INVALID-ID-INFORMATION", 23: "INVALID-HASH-INFORMATION", 24: "AUTHENTICATION-FAILED",
}

func notifyError(n uint16) error {
	name := v1Notify[n]
	if name == "" {
		name = fmt.Sprintf("error %d", n)
	}
	switch n {
	case 14, 13:
		return fmt.Errorf("the server accepted none of komando's proposals (%s): it may want ciphers komando does not speak", name)
	case 24, 23, 7:
		return &AuthError{Msg: "the server refused the login (" + name + "): check the pre-shared key and the group name"}
	case 18:
		return &AuthError{Msg: "the server does not know this client (" + name + "): check the group name"}
	case 16, 1:
		return &AuthError{Msg: "the server could not read komando's login (" + name + "): usually a wrong pre-shared key"}
	}
	return errors.New("the server sent " + name)
}

// The IKEv1 SA.

type v1msg struct {
	exch, flags byte
	rc          []byte
	mid         uint32
	ps          []v1Payload
	enc         bool
}

type ikeV1 struct {
	t   *udpTransport
	s   *Session
	o   *Options
	in  chan []byte
	tun bool // tunnel mode (Cisco); else L2TP transport mode

	mu        sync.Mutex
	ic, rc    []byte
	suite     p1Suite
	dh        dhGroup
	ni, nr    []byte
	gxi       []byte
	gxr       []byte
	skeyid    []byte
	sD, sA    []byte
	key       []byte
	p1IV      []byte
	ivs       map[uint32][]byte
	lastIn    map[uint32][]byte
	lastOut   map[uint32][]byte
	pending   map[uint32]chan v1msg
	txn       chan v1msg
	p1err     chan error
	natD      byte
	natOA     byte
	encapT    uint16        // UDP-Transport
	encapU    uint16        // UDP-Tunnel
	life      time.Duration // the IKE SA's
	childLife time.Duration // the ESP SA's
	dpdSeq    uint32
	dpdAck    bool
	dpd       bool // the server does dead peer detection
	pfs       bool
	ended     bool
	onDelete  func()
	onESPLost func() // the server deleted the ESP SA in use
}

func newIKEv1(t *udpTransport, s *Session, o *Options, tun bool) *ikeV1 {
	k := &ikeV1{t: t, s: s, o: o, tun: tun, ic: random(8), rc: make([]byte, 8), ivs: map[uint32][]byte{},
		lastIn: map[uint32][]byte{}, lastOut: map[uint32][]byte{}, pending: map[uint32]chan v1msg{},
		txn: make(chan v1msg, 8), p1err: make(chan error, 1)}
	k.in = t.route(k.ic)
	go k.run()
	return k
}

func (k *ikeV1) bs() int { return k.suite.enc.blockSize() }

func (k *ikeV1) header(exch, flags byte, mid uint32, next byte, length int) []byte {
	h := make([]byte, v1HdrLen)
	copy(h, k.ic)
	copy(h[8:], k.rc)
	h[16], h[17], h[18], h[19] = next, 0x10, exch, flags
	binary.BigEndian.PutUint32(h[20:], mid)
	binary.BigEndian.PutUint32(h[24:], uint32(length))
	return h
}

func (k *ikeV1) plain(exch byte, mid uint32, ps []v1Payload) []byte {
	first, body := encodeChain(ps)
	return append(k.header(exch, 0, mid, first, v1HdrLen+len(body)), body...)
}

// iv is the CBC IV for the next message of an exchange (k.mu held).
func (k *ikeV1) iv(mid uint32) []byte {
	if v, ok := k.ivs[mid]; ok {
		return v
	}
	base := k.p1IV
	if base == nil {
		// phase 1 just ended and the server already sent more (INITIAL-CONTACT):
		// its last CBC block is the phase 1 IV
		base = k.ivs[0]
	}
	return k.suite.hash.sum(base, binary.BigEndian.AppendUint32(nil, mid))[:k.bs()]
}

func (k *ikeV1) encrypted(exch byte, mid uint32, ps []v1Payload) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	first, body := encodeChain(ps)
	bs := k.bs()
	if pad := (bs - len(body)%bs) % bs; pad > 0 {
		body = append(body, make([]byte, pad)...)
	}
	ct, err := cbcEncrypt(k.suite.enc, k.key, k.iv(mid), body)
	if err != nil {
		return nil, err
	}
	k.ivs[mid] = append([]byte{}, ct[len(ct)-bs:]...)
	msg := append(k.header(exch, flagEnc, mid, first, v1HdrLen+len(ct)), ct...)
	k.lastOut[mid] = msg
	return msg, nil
}

// parse decrypts and splits a message. Retransmissions of a message
// already seen get our last answer again and are dropped.
func (k *ikeV1) parse(raw []byte) (*v1msg, error) {
	if len(raw) < v1HdrLen || raw[17]>>4 != 1 {
		return nil, errors.New("not IKEv1")
	}
	n := int(binary.BigEndian.Uint32(raw[24:]))
	if n > len(raw) || n < v1HdrLen {
		return nil, errors.New("bad length")
	}
	raw = raw[:n]
	m := &v1msg{exch: raw[18], flags: raw[19], rc: raw[8:16], mid: binary.BigEndian.Uint32(raw[20:])}
	k.mu.Lock()
	defer k.mu.Unlock()
	if prev, ok := k.lastIn[m.mid]; ok && bytes.Equal(prev, raw) {
		if out := k.lastOut[m.mid]; out != nil {
			k.t.sendIKE(out)
		}
		return nil, nil
	}
	k.lastIn[m.mid] = append([]byte{}, raw...)
	body := raw[v1HdrLen:]
	if m.flags&flagEnc != 0 {
		if k.key == nil {
			return nil, errors.New("encrypted message before the keys")
		}
		bs := k.bs()
		if len(body) == 0 || len(body)%bs != 0 {
			return nil, errors.New("bad encrypted length")
		}
		pt, err := cbcDecrypt(k.suite.enc, k.key, k.iv(m.mid), body)
		if err != nil {
			return nil, err
		}
		k.ivs[m.mid] = append([]byte{}, body[len(body)-bs:]...)
		body, m.enc = pt, true
	}
	ps, err := parseChain(raw[16], body)
	if err != nil {
		return nil, err
	}
	m.ps = ps
	return m, nil
}

// run reads the SA's messages: answers to our requests go to their
// waiter, the rest (DPD, deletes, server rekeys, XAUTH) are handled here.
func (k *ikeV1) run() {
	for {
		select {
		case <-k.t.done:
			return
		case raw := <-k.in:
			k.o.debugf("IKEv1: received %d bytes (exchange %d)", len(raw), raw[18])
			m, err := k.parse(raw)
			if err != nil {
				k.o.logf("IKEv1: dropped a message: %v", err)
				continue
			}
			if m == nil {
				continue
			}
			k.mu.Lock()
			ch := k.pending[m.mid]
			k.mu.Unlock()
			if ch != nil && (m.exch != exInfo || m.mid == 0) {
				select {
				case ch <- *m:
				default:
				}
				continue
			}
			k.unsolicited(m)
		}
	}
}

// roundTrip sends msg and waits for the server's answer in the same
// exchange, sending again when none comes.
func (k *ikeV1) roundTrip(ctx context.Context, mid uint32, msg []byte) (v1msg, error) {
	ch := make(chan v1msg, 4)
	k.mu.Lock()
	k.pending[mid] = ch
	k.lastOut[mid] = msg
	k.mu.Unlock()
	defer func() {
		k.mu.Lock()
		delete(k.pending, mid)
		k.mu.Unlock()
	}()
	select { // an old error belongs to an exchange that is over
	case <-k.p1err:
	default:
	}
	wait := time.Second
	for try := 0; try < 7; try++ {
		k.o.debugf("IKEv1: sending %d bytes (exchange %d, message %d, try %d) to %s", len(msg), msg[18], mid, try+1, k.t.server)
		if err := k.t.sendIKE(msg); err != nil {
			return v1msg{}, err
		}
		timer := time.NewTimer(wait)
		select {
		case m := <-ch:
			timer.Stop()
			return m, nil
		case err := <-k.p1err:
			timer.Stop()
			return v1msg{}, err
		case <-ctx.Done():
			timer.Stop()
			return v1msg{}, ctx.Err()
		case <-k.t.done:
			timer.Stop()
			return v1msg{}, fmt.Errorf("the connection ended: %v", k.t.err)
		case <-timer.C:
			wait = min(wait*2, 8*time.Second)
		}
	}
	return v1msg{}, errors.New("no answer from the server")
}

// Phase 1.

func (k *ikeV1) vids() []v1Payload {
	var ps []v1Payload
	for _, v := range [][]byte{vidRFC3947, vidDraft03, vidDraft02n, vidDraft02, vidDPD} {
		ps = append(ps, v1Payload{typ: plVID, body: v})
	}
	if k.tun {
		ps = append(ps, v1Payload{typ: plVID, body: vidXAUTH}, v1Payload{typ: plVID, body: vidUnity})
	}
	return ps
}

// readVIDs notes which NAT traversal flavour the server speaks.
func (k *ikeV1) readVIDs(ps []v1Payload) error {
	for _, p := range ps {
		if p.typ != plVID {
			continue
		}
		switch {
		case bytes.Equal(p.body, vidRFC3947):
			k.natD, k.natOA, k.encapT, k.encapU = plNatD, plNatOA, 4, 3
		case bytes.Equal(p.body, vidDPD[:len(vidDPD)-2]) || bytes.Equal(p.body, vidDPD):
			k.dpd = true
		case k.natD == 0 && (bytes.Equal(p.body, vidDraft02) || bytes.Equal(p.body, vidDraft02n) || bytes.Equal(p.body, vidDraft03)):
			k.natD, k.natOA, k.encapT, k.encapU = plNatDd, plNatOAd, 61444, 61443
		}
	}
	if k.natD == 0 {
		return errors.New("the server does not support NAT traversal (RFC 3947), which komando needs to run without admin rights")
	}
	return nil
}

// natDs are the NAT-D payloads: the server's address, then ours made up,
// so the server always sees a NAT and both sides move ESP into UDP.
func (k *ikeV1) natDs() []v1Payload {
	srv := k.t.server.As4()
	port := binary.BigEndian.AppendUint16(nil, uint16(k.t.port))
	return []v1Payload{
		{typ: k.natD, body: k.suite.hash.sum(k.ic, k.rc, srv[:], port)},
		{typ: k.natD, body: k.suite.hash.sum(k.ic, k.rc, random(4), random(2))},
	}
}

func (k *ikeV1) ourID() []byte {
	if k.o.ID != "" {
		return append([]byte{idKeyID, 0, 0, 0}, k.o.ID...)
	}
	a := k.t.local().Addr().As4()
	return append([]byte{idIPv4, 0, 0, 0}, a[:]...)
}

func (k *ikeV1) authMethod() uint16 {
	if k.tun && k.o.User != "" {
		return 65001 // XAUTHInitPreShared
	}
	return 1 // pre-shared key
}

// lifetime of the IKE SA: 8 hours, or three ESP lifetimes when a test
// shortens them.
func (k *ikeV1) lifetime() uint32 {
	if k.o.Lifetime > 0 {
		return uint32(3 * k.o.Lifetime / time.Second)
	}
	return 28800
}

// keys derives SKEYID and the phase 1 keys (RFC 2409 5).
func (k *ikeV1) keys(gxy []byte) {
	h := k.suite.hash
	k.skeyid = h.prf([]byte(k.o.PSK), k.ni, k.nr)
	k.sD = h.prf(k.skeyid, gxy, k.ic, k.rc, []byte{0})
	k.sA = h.prf(k.skeyid, k.sD, gxy, k.ic, k.rc, []byte{1})
	sE := h.prf(k.skeyid, k.sA, gxy, k.ic, k.rc, []byte{2})
	key := sE
	if len(key) < k.suite.enc.key {
		key = nil
		for prev := []byte{0}; len(key) < k.suite.enc.key; {
			prev = h.prf(sE, prev)
			key = append(key, prev...)
		}
	}
	k.key = key[:k.suite.enc.key]
	k.ivs[0] = h.sum(k.gxi, k.gxr)[:k.bs()]
}

func (k *ikeV1) hashI(sai, idi []byte) []byte {
	return k.suite.hash.prf(k.skeyid, k.gxi, k.gxr, k.ic, k.rc, sai, idi)
}

func (k *ikeV1) hashR(sai, idr []byte) []byte {
	return k.suite.hash.prf(k.skeyid, k.gxr, k.gxi, k.rc, k.ic, sai, idr)
}

// acceptP1 takes the suite the server chose, which must be one komando
// offered: a server cannot pick a weaker cipher, hash or DH group than
// the ones in the offer.
func (k *ikeV1) acceptP1(sa *v1Payload, offered []p1Suite) error {
	if sa == nil {
		return errors.New("the server's answer has no SA")
	}
	c, err := parseChosen(sa.body)
	if err != nil {
		return err
	}
	s, err := suiteFromP1(c.attrs)
	if err != nil {
		return fmt.Errorf("the server chose a proposal komando did not offer: %v", err)
	}
	if !offersP1(offered, s) {
		return fmt.Errorf("the server chose %s, which komando did not offer", s)
	}
	k.suite = s
	if life := attrNum(c.attrs, 12); life > 0 {
		k.life = time.Duration(life) * time.Second
	}
	return nil
}

func (k *ikeV1) mainMode(ctx context.Context) error {
	sai, offered := p1SA(p1Offer(k.o.LegacyCrypto), k.authMethod(), k.lifetime(), 0)
	r, err := k.roundTrip(ctx, 0, k.plain(exMain, 0, append([]v1Payload{{typ: plSA, body: sai}}, k.vids()...)))
	if err != nil {
		return p1Err(err)
	}
	copy(k.rc, r.rc)
	if err := k.acceptP1(find(r.ps, plSA), offered); err != nil {
		return err
	}
	if err := k.readVIDs(r.ps); err != nil {
		return err
	}
	if k.dh, err = newDH(k.suite.group); err != nil {
		return err
	}
	k.gxi, k.ni = k.dh.Public(), random(32)
	ps := append([]v1Payload{{typ: plKE, body: k.gxi}, {typ: plNonce, body: k.ni}}, k.natDs()...)
	r, err = k.roundTrip(ctx, 0, k.plain(exMain, 0, ps))
	if err != nil {
		return p1Err(err)
	}
	ke, nr := find(r.ps, plKE), find(r.ps, plNonce)
	if ke == nil || nr == nil {
		return errors.New("the server's answer has no key exchange")
	}
	k.gxr, k.nr = ke.body, nr.body
	gxy, err := k.dh.Shared(k.gxr)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.keys(gxy)
	k.mu.Unlock()
	if err := k.t.startNATT(); err != nil {
		return err
	}
	idi := k.ourID()
	msg, err := k.encrypted(exMain, 0, []v1Payload{{typ: plID, body: idi}, {typ: plHash, body: k.hashI(sai, idi)}})
	if err != nil {
		return err
	}
	r, err = k.roundTrip(ctx, 0, msg)
	if err != nil {
		if err.Error() == "no answer from the server" {
			return &AuthError{Msg: "the server did not answer the login: usually a wrong pre-shared key"}
		}
		return p1Err(err)
	}
	idr, hr := find(r.ps, plID), find(r.ps, plHash)
	if idr == nil || hr == nil || !bytes.Equal(hr.body, k.hashR(sai, idr.body)) {
		return &AuthError{Msg: "the server's proof of the pre-shared key is wrong (a wrong key, or not the right server)"}
	}
	k.mu.Lock()
	k.p1IV = k.ivs[0]
	k.mu.Unlock()
	return nil
}

func (k *ikeV1) aggressiveOnce(ctx context.Context, group uint16) error {
	sai, offered := p1SA(p1Offer(k.o.LegacyCrypto), k.authMethod(), k.lifetime(), group)
	var err error
	if k.dh, err = newDH(group); err != nil {
		return err
	}
	k.gxi, k.ni = k.dh.Public(), random(32)
	idi := k.ourID()
	ps := []v1Payload{{typ: plSA, body: sai}, {typ: plKE, body: k.gxi}, {typ: plNonce, body: k.ni}, {typ: plID, body: idi}}
	r, err := k.roundTrip(ctx, 0, k.plain(exAggr, 0, append(ps, k.vids()...)))
	if err != nil {
		return p1Err(err)
	}
	copy(k.rc, r.rc)
	if err := k.acceptP1(find(r.ps, plSA), offered); err != nil {
		return err
	}
	if err := k.readVIDs(r.ps); err != nil {
		return err
	}
	ke, nr, idr, hr := find(r.ps, plKE), find(r.ps, plNonce), find(r.ps, plID), find(r.ps, plHash)
	if ke == nil || nr == nil || idr == nil || hr == nil {
		return errors.New("the server's answer is incomplete")
	}
	k.gxr, k.nr = ke.body, nr.body
	gxy, err := k.dh.Shared(k.gxr)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.keys(gxy)
	k.mu.Unlock()
	if !bytes.Equal(hr.body, k.hashR(sai, idr.body)) {
		return &AuthError{Msg: "the server's proof of the pre-shared key is wrong (a wrong group password, or not the right server)"}
	}
	if err := k.t.startNATT(); err != nil {
		return err
	}
	// the third message is not encrypted (RFC 2409 5.4)
	msg := k.plain(exAggr, 0, append([]v1Payload{{typ: plHash, body: k.hashI(sai, idi)}}, k.natDs()...))
	if err := k.t.sendIKE(msg); err != nil {
		return err
	}
	k.mu.Lock()
	k.lastOut[0] = msg
	k.p1IV = k.ivs[0]
	k.mu.Unlock()
	return nil
}

func p1Err(err error) error {
	if err != nil && err.Error() == "no answer from the server" {
		return errors.New("the VPN server does not answer on UDP 500 (IKE): check the address and that UDP 500 and 4500 are open")
	}
	return err
}

// Protected exchanges (HASH(1) first).

func (k *ikeV1) hash1(mid uint32, rest []byte) []byte {
	return k.suite.hash.prf(k.sA, binary.BigEndian.AppendUint32(nil, mid), rest)
}

func (k *ikeV1) protected(exch byte, mid uint32, ps []v1Payload) ([]byte, error) {
	_, rest := encodeChain(ps)
	return k.encrypted(exch, mid, append([]v1Payload{{typ: plHash, body: k.hash1(mid, rest)}}, ps...))
}

// verify checks HASH(1)-style hashes: the hash payload first, over the
// rest. extra goes between M-ID and the rest (Ni_b for quick mode 2).
func (k *ikeV1) verify(m v1msg, extra []byte) bool {
	if len(m.ps) == 0 || m.ps[0].typ != plHash || !m.enc {
		return false
	}
	var rest []byte
	for _, p := range m.ps[1:] {
		rest = append(rest, p.raw...)
	}
	// the last payload's next-payload byte is 0 as sent
	want := k.suite.hash.prf(k.sA, binary.BigEndian.AppendUint32(nil, m.mid), extra, rest)
	return bytes.Equal(m.ps[0].body, want)
}

func newMID() uint32 {
	for {
		if m := binary.BigEndian.Uint32(random(4)); m != 0 {
			return m
		}
	}
}

// XAUTH and Mode Config.

const (
	cfgReq = 1
	cfgRep = 2
	cfgSet = 3
	cfgAck = 4

	xauthType   = 16520
	xauthUser   = 16521
	xauthPass   = 16522
	xauthCode   = 16523
	xauthMsg    = 16524
	xauthChal   = 16525
	xauthDomain = 16526
	xauthStatus = 16527
	xauthNext   = 16528
	xauthAnswer = 16529

	cfgIP4Addr = 1
	cfgIP4Mask = 2
	cfgIP4DNS  = 3
)

func attrPayload(typ byte, id uint16, attrs []byte) v1Payload {
	b := []byte{typ, 0}
	b = binary.BigEndian.AppendUint16(b, id)
	return v1Payload{typ: plAttr, body: append(b, attrs...)}
}

// xauth answers the server's login requests until it says yes or no.
func (k *ikeV1) xauth(ctx context.Context) error {
	tries := 0
	for {
		var m v1msg
		select {
		case m = <-k.txn:
		case <-ctx.Done():
			return ctx.Err()
		case <-k.t.done:
			return fmt.Errorf("the connection ended: %v", k.t.err)
		case <-time.After(30 * time.Second):
			if tries == 0 {
				k.o.logf("IKEv1: the server asked for no XAUTH login")
				return nil
			}
			return errors.New("the XAUTH login got no answer")
		}
		ap := find(m.ps, plAttr)
		if ap == nil || len(ap.body) < 4 || !k.verify(m, nil) {
			continue
		}
		typ, id := ap.body[0], binary.BigEndian.Uint16(ap.body[2:])
		as := parseAttrs(ap.body[4:])
		k.o.logf("IKEv1: XAUTH message %d from the server", typ)
		switch typ {
		case cfgReq:
			tries++
			if tries > 3 {
				return &AuthError{Msg: "the server keeps asking for the XAUTH login"}
			}
			var reply []byte
			for _, a := range as {
				switch a.t {
				case xauthType:
					reply = append(reply, attrTV(xauthType, uint16(a.num()))...)
				case xauthUser:
					reply = append(reply, attrTLV(xauthUser, []byte(k.o.User))...)
				case xauthPass:
					reply = append(reply, attrTLV(xauthPass, []byte(k.o.Password))...)
				case xauthCode, xauthAnswer, xauthNext:
					if k.o.Prompt == nil {
						return ErrNeedsPerson
					}
					label := "One-time code"
					if msg := attrString(as, xauthMsg); msg != "" {
						label = msg
					}
					code, err := k.o.Prompt(label, a.t != xauthNext)
					if err != nil {
						return err
					}
					reply = append(reply, attrTLV(a.t, []byte(code))...)
				}
			}
			out, err := k.protected(exTxn, m.mid, []v1Payload{attrPayload(cfgRep, id, reply)})
			if err != nil {
				return err
			}
			k.sendLast(m.mid, out)
		case cfgSet:
			out, err := k.protected(exTxn, m.mid, []v1Payload{attrPayload(cfgAck, id, attrTV(xauthStatus, uint16(attrNum(as, xauthStatus))))})
			if err != nil {
				return err
			}
			k.sendLast(m.mid, out)
			if attrNum(as, xauthStatus) != 1 {
				return &AuthError{Msg: "the VPN refused the login (XAUTH): check the user name and password"}
			}
			return nil
		}
	}
}

func attrString(as []attr, t uint16) string {
	for _, a := range as {
		if a.t == t {
			return clean(string(a.v))
		}
	}
	return ""
}

func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && b.Len() < 200 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (k *ikeV1) sendLast(mid uint32, out []byte) {
	k.mu.Lock()
	k.lastOut[mid] = out
	k.mu.Unlock()
	k.t.sendIKE(out)
}

// modeConfig asks for an address and DNS servers (pull), or takes the
// ones the server pushes.
func (k *ikeV1) modeConfig(ctx context.Context) error {
	mid := newMID()
	req := append(attrTLV(cfgIP4Addr, nil), attrTLV(cfgIP4Mask, nil)...)
	req = append(req, attrTLV(cfgIP4DNS, nil)...)
	out, err := k.protected(exTxn, mid, []v1Payload{attrPayload(cfgReq, 1, req)})
	if err != nil {
		return err
	}
	// a push may already be waiting
	select {
	case m := <-k.txn:
		if ok, err := k.takeConfig(m); ok || err != nil {
			return err
		}
	default:
	}
	m, err := k.roundTrip(ctx, mid, out)
	if err != nil {
		return fmt.Errorf("mode config: %v", err)
	}
	_, err = k.takeConfig(m)
	return err
}

func (k *ikeV1) takeConfig(m v1msg) (bool, error) {
	ap := find(m.ps, plAttr)
	if ap == nil || len(ap.body) < 4 || !k.verify(m, nil) {
		return false, nil
	}
	typ := ap.body[0]
	if typ != cfgRep && typ != cfgSet {
		return false, nil
	}
	var addr netip.Addr
	for _, a := range parseAttrs(ap.body[4:]) {
		if len(a.v) != 4 {
			continue
		}
		v := netip.AddrFrom4([4]byte(a.v))
		switch a.t {
		case cfgIP4Addr:
			addr = v
		case cfgIP4DNS:
			if !slices.Contains(k.s.DNS, v) {
				k.s.DNS = append(k.s.DNS, v)
			}
		}
	}
	if addr.IsValid() {
		if k.s.Address.IsValid() && k.s.Address != addr {
			return true, fmt.Errorf("the server gave another address (%s, before %s) to the new IKE SA", addr, k.s.Address)
		}
		k.s.Address = addr
	}
	if typ == cfgSet {
		out, err := k.protected(exTxn, m.mid, []v1Payload{attrPayload(cfgAck, binary.BigEndian.Uint16(ap.body[2:]), nil)})
		if err == nil {
			k.sendLast(m.mid, out)
		}
	}
	if !k.s.Address.IsValid() {
		return true, errors.New("the server gave no address (mode config)")
	}
	return true, nil
}

// Quick mode.

func (k *ikeV1) espLife() uint32 {
	if k.o.Lifetime > 0 {
		return uint32(k.o.Lifetime / time.Second)
	}
	return 3600
}

func (k *ikeV1) quickIDs() []v1Payload {
	if k.tun {
		a := k.s.Address.As4()
		return []v1Payload{
			{typ: plID, body: append([]byte{idIPv4, 0, 0, 0}, a[:]...)},
			{typ: plID, body: []byte{idIPv4Subnet, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		}
	}
	l, r := k.t.local().Addr().As4(), k.t.server.As4()
	return []v1Payload{
		{typ: plID, body: append([]byte{idIPv4, 17, 0x06, 0xa5}, l[:]...)}, // UDP 1701
		{typ: plID, body: append([]byte{idIPv4, 17, 0x06, 0xa5}, r[:]...)},
	}
}

func (k *ikeV1) keymat(spi, ni, nr, gqm []byte, n int) []byte {
	h := k.suite.hash
	var out, prev []byte
	for len(out) < n {
		prev = h.prf(k.sD, prev, gqm, []byte{3}, spi, ni, nr)
		out = append(out, prev...)
	}
	return out[:n]
}

// quickMode sets up a new pair of ESP SAs and installs them.
func (k *ikeV1) quickMode(ctx context.Context) error {
	err := k.quickOnce(ctx, k.pfs)
	if err != nil && !k.pfs && strings.Contains(err.Error(), "accepted none") {
		k.o.logf("IKEv1: quick mode without PFS refused; trying with PFS")
		k.pfs = true
		err = k.quickOnce(ctx, true)
	}
	return legacyHint(k.o, err)
}

func (k *ikeV1) quickOnce(ctx context.Context, pfs bool) error {
	mid := newMID()
	spi := random(4)
	encap := k.encapT
	if k.tun {
		encap = k.encapU
	}
	var group uint16
	var dh dhGroup
	var err error
	if pfs {
		group = k.suite.group
		if dh, err = newDH(group); err != nil {
			return err
		}
	}
	offered := espOffer(k.o.LegacyCrypto)
	ts := espTransformsV1(offered, encap, k.espLife(), group)
	ni := random(32)
	ps := []v1Payload{{typ: plSA, body: proposal(1, 3, spi, ts)}, {typ: plNonce, body: ni}}
	if dh != nil {
		ps = append(ps, v1Payload{typ: plKE, body: dh.Public()})
	}
	ps = append(ps, k.quickIDs()...)
	if !k.tun { // transport mode behind NAT: our real addresses (RFC 3947 5.2)
		l, r := k.t.local().Addr().As4(), k.t.server.As4()
		ps = append(ps, v1Payload{typ: k.natOA, body: append([]byte{idIPv4, 0, 0, 0}, l[:]...)},
			v1Payload{typ: k.natOA, body: append([]byte{idIPv4, 0, 0, 0}, r[:]...)})
	}
	out, err := k.protected(exQuick, mid, ps)
	if err != nil {
		return err
	}
	r, err := k.roundTrip(ctx, mid, out)
	if err != nil {
		return fmt.Errorf("quick mode: %v", err)
	}
	if n := find(r.ps, plNotify); n != nil && len(n.body) >= 8 && find(r.ps, plSA) == nil {
		return notifyError(binary.BigEndian.Uint16(n.body[6:]))
	}
	if !k.verify(r, ni) {
		return errors.New("quick mode: the server's hash is wrong")
	}
	sa, nr := find(r.ps, plSA), find(r.ps, plNonce)
	if sa == nil || nr == nil {
		return errors.New("quick mode: the server's answer is incomplete")
	}
	c, err := parseChosen(sa.body)
	if err != nil {
		return err
	}
	suite, err := offeredESPv1(c, offered)
	if err != nil {
		return err
	}
	if len(c.spi) != 4 {
		return errors.New("quick mode: bad SPI")
	}
	var gqm []byte
	if dh != nil {
		ke := find(r.ps, plKE)
		if ke == nil {
			return errors.New("quick mode: no key exchange for PFS")
		}
		if gqm, err = dh.Shared(ke.body); err != nil {
			return err
		}
	}
	life := time.Duration(attrNum(c.attrs, 2)) * time.Second
	for _, p := range r.ps {
		if p.typ == plNotify && len(p.body) >= 8 && binary.BigEndian.Uint16(p.body[6:]) == 24576 { // RESPONDER-LIFETIME
			spiLen := int(p.body[5])
			if len(p.body) >= 8+spiLen {
				if l := attrNum(parseAttrs(p.body[8+spiLen:]), 2); l > 0 {
					life = time.Duration(l) * time.Second
				}
			}
		}
	}
	in := suite.split(k.keymat(spi, ni, nr.body, gqm, suite.keyLen()))
	o := suite.split(k.keymat(c.spi, ni, nr.body, gqm, suite.keyLen()))
	esp, err := newESP(suite, binary.BigEndian.Uint32(spi), binary.BigEndian.Uint32(c.spi), in, o)
	if err != nil {
		return err
	}
	h3 := k.suite.hash.prf(k.sA, []byte{0}, binary.BigEndian.AppendUint32(nil, mid), ni, nr.body)
	out, err = k.encrypted(exQuick, mid, []v1Payload{{typ: plHash, body: h3}})
	if err != nil {
		return err
	}
	k.sendLast(mid, out)
	k.s.install(esp)
	if life <= 0 {
		life = time.Duration(k.espLife()) * time.Second
	}
	k.mu.Lock()
	k.childLife = life
	k.mu.Unlock()
	k.o.logf("IKEv1: ESP up (%s, SPI %08x/%08x, lifetime %s)", suite, esp.spiIn, esp.spiOut, life)
	return nil
}

// Messages the server starts.

func (k *ikeV1) unsolicited(m *v1msg) {
	switch m.exch {
	case exTxn:
		select {
		case k.txn <- *m:
		default:
		}
	case exInfo:
		if !m.enc {
			// an unprotected error during phase 1
			if n := find(m.ps, plNotify); n != nil && len(n.body) >= 8 && k.p1IV == nil {
				select {
				case k.p1err <- notifyError(binary.BigEndian.Uint16(n.body[6:])):
				default:
				}
			}
			return
		}
		if !k.verify(*m, nil) {
			return
		}
		for _, p := range m.ps[1:] {
			switch p.typ {
			case plNotify:
				if len(p.body) >= 8 {
					if t := binary.BigEndian.Uint16(p.body[6:]); t > 0 && t < 8192 {
						select { // an error for the exchange under way
						case k.p1err <- notifyError(t):
						default:
						}
						continue
					}
				}
				k.notify(p.body)
			case plDelete:
				k.deleted(p.body)
			}
		}
	case exQuick:
		k.quickResponder(m)
	}
}

func (k *ikeV1) notify(b []byte) {
	if len(b) < 8 {
		return
	}
	spiLen := int(b[5])
	typ := binary.BigEndian.Uint16(b[6:])
	if len(b) < 8+spiLen {
		return
	}
	data := b[8+spiLen:]
	switch typ {
	case 36136: // R-U-THERE
		if len(data) >= 4 {
			k.info([]v1Payload{{typ: plNotify, body: k.dpdBody(36137, data[:4])}})
		}
	case 36137: // R-U-THERE-ACK
		k.mu.Lock()
		k.dpdAck = true
		k.mu.Unlock()
	}
}

func (k *ikeV1) dpdBody(typ uint16, seq []byte) []byte {
	b := []byte{0, 0, 0, 1, 1, 16}
	b = binary.BigEndian.AppendUint16(b, typ)
	b = append(append(b, k.ic...), k.rc...)
	return append(b, seq...)
}

func (k *ikeV1) deleted(b []byte) {
	if len(b) < 8 {
		return
	}
	proto, spiLen, n := b[4], int(b[5]), int(binary.BigEndian.Uint16(b[6:]))
	spis := b[8:]
	switch proto {
	case 1: // ISAKMP: the server ended the IKE SA
		k.mu.Lock()
		gone := !k.ended
		k.ended = true
		k.mu.Unlock()
		if gone && k.onDelete != nil {
			k.onDelete()
		}
	case 3:
		for i := 0; i < n && len(spis) >= spiLen*(i+1) && spiLen == 4; i++ {
			if k.s.remove(binary.BigEndian.Uint32(spis[4*i:])) {
				if k.onESPLost != nil {
					k.o.logf("IKEv1: the server deleted the ESP SA in use; making a new one")
					go k.onESPLost()
				} else {
					k.s.end(errors.New("the server ended the session"))
				}
			}
		}
	}
}

func (k *ikeV1) info(ps []v1Payload) {
	mid := newMID()
	if out, err := k.protected(exInfo, mid, ps); err == nil {
		k.t.sendIKE(out)
	}
}

// deleteIKE tells the server to drop the IKE SA.
func (k *ikeV1) deleteIKE() {
	b := append([]byte{0, 0, 0, 1, 1, 16, 0, 1}, k.ic...)
	k.info([]v1Payload{{typ: plDelete, body: append(b, k.rc...)}})
}

// deleteSAs tells the server komando is leaving.
func (k *ikeV1) deleteSAs() {
	if sa := k.s.currentOut(); sa != nil {
		b := []byte{0, 0, 0, 1, 3, 4, 0, 1}
		k.info([]v1Payload{{typ: plDelete, body: binary.BigEndian.AppendUint32(b, sa.spiIn)}})
	}
	b := append([]byte{0, 0, 0, 1, 1, 16, 0, 1}, k.ic...)
	k.info([]v1Payload{{typ: plDelete, body: append(b, k.rc...)}})
}

// quickResponder answers a quick mode the server starts (its rekey).
func (k *ikeV1) quickResponder(m *v1msg) {
	if !k.verify(*m, nil) {
		return
	}
	sa, ni := find(m.ps, plSA), find(m.ps, plNonce)
	if sa == nil || ni == nil {
		return
	}
	// the server's proposal: pick the first transform komando speaks
	body := sa.body
	if len(body) < 12 {
		return
	}
	p := body[8:]
	pl := int(binary.BigEndian.Uint16(p[2:]))
	if pl > len(p) || pl < 8 {
		return
	}
	p = p[4:pl]
	spiLen, nt := int(p[2]), int(p[3])
	if spiLen != 4 || len(p) < 8 {
		return
	}
	peerSPI := p[4:8]
	ts := p[8:]
	var pick []byte
	var suite espSuite
	for i := 0; i < nt && len(ts) >= 8; i++ {
		tl := int(binary.BigEndian.Uint16(ts[2:]))
		if tl < 8 || tl > len(ts) {
			return
		}
		c := chosen{tid: ts[5], attrs: parseAttrs(ts[8:tl])}
		g := uint16(attrNum(c.attrs, 3)) // the PFS group, if any
		if s, err := suiteFromESPv1(c); err == nil && offersESP(espOffer(k.o.LegacyCrypto), s) && (!weakGroup(g) || k.o.LegacyCrypto) {
			pick, suite = ts[:tl], s
			break
		}
		ts = ts[tl:]
	}
	if pick == nil {
		k.o.logf("IKEv1: the server's rekey offers nothing komando speaks (weak ciphers need legacy crypto)")
		return
	}
	t := append([]byte{}, pick[4:]...)
	t[0] = 1
	spi := random(4)
	nr := random(32)
	var gqm []byte
	var reply []v1Payload
	reply = append(reply, v1Payload{typ: plSA, body: proposal(1, 3, spi, [][]byte{t})}, v1Payload{typ: plNonce, body: nr})
	if ke := find(m.ps, plKE); ke != nil {
		dh, err := newDH(uint16(attrNum(parseAttrs(pick[8:]), 3)))
		if err != nil {
			return
		}
		if gqm, err = dh.Shared(ke.body); err != nil {
			return
		}
		reply = append(reply, v1Payload{typ: plKE, body: dh.Public()})
	}
	for _, x := range m.ps {
		if x.typ == plID || x.typ == k.natOA {
			reply = append(reply, v1Payload{typ: x.typ, body: x.body})
		}
	}
	_, rest := encodeChain(reply)
	h2 := k.suite.hash.prf(k.sA, binary.BigEndian.AppendUint32(nil, m.mid), ni.body, rest)
	in := suite.split(k.keymat(spi, ni.body, nr, gqm, suite.keyLen()))
	o := suite.split(k.keymat(peerSPI, ni.body, nr, gqm, suite.keyLen()))
	esp, err := newESP(suite, binary.BigEndian.Uint32(spi), binary.BigEndian.Uint32(peerSPI), in, o)
	if err != nil {
		return
	}
	out, err := k.encrypted(exQuick, m.mid, append([]v1Payload{{typ: plHash, body: h2}}, reply...))
	if err != nil {
		return
	}
	k.sendLast(m.mid, out)
	// the server's third message confirms; install now, packets on the old
	// SA still arrive meanwhile
	k.s.install(esp)
	k.o.logf("IKEv1: the server rekeyed ESP (%s, SPI %08x/%08x)", suite, esp.spiIn, esp.spiOut)
}
