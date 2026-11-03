package openvpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"sync"
	"time"
)

// opcodes (the high five bits of the first byte; the low three are the key id)
const (
	opControlSoftResetV1       = 3
	opControlV1                = 4
	opAckV1                    = 5
	opDataV1                   = 6
	opControlHardResetClientV2 = 7
	opControlHardResetServerV2 = 8
	opDataV2                   = 9
)

// ctrlWrap protects control packets: nothing, tls-auth (an HMAC) or
// tls-crypt (AES-256-CTR plus HMAC-SHA256).
type ctrlWrap interface {
	// wrap builds the wire packet from the header and body (acks,
	// message id, payload)
	wrap(op byte, sid [8]byte, body []byte) []byte
	unwrap(pkt []byte) (op byte, sid [8]byte, body []byte, err error)
}

type plainWrap struct{}

func (plainWrap) wrap(op byte, sid [8]byte, body []byte) []byte {
	return append(append([]byte{op}, sid[:]...), body...)
}

func (plainWrap) unwrap(p []byte) (byte, [8]byte, []byte, error) {
	var sid [8]byte
	if len(p) < 9 {
		return 0, sid, nil, errShort
	}
	copy(sid[:], p[1:9])
	return p[0], sid, p[9:], nil
}

var errShort = errors.New("short packet")

// replayHeader is the packet id and time tls-auth and tls-crypt add.
type replayHeader struct {
	mu   sync.Mutex
	pid  uint32
	when uint32
	win  replay
}

func (r *replayHeader) next() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pid++
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, r.pid)
	binary.BigEndian.PutUint32(b[4:], r.when)
	return b
}

type authWrap struct {
	send, recv []byte
	digest     func() hash.Hash
	rh         replayHeader
}

func newAuthWrap(key []byte, direction int, digest string) (*authWrap, error) {
	d, ok := digests[digest]
	if !ok {
		return nil, errors.New("tls-auth needs auth SHA1, SHA256, SHA384 or SHA512")
	}
	send, recv := keyPair(key, direction)
	n := d().Size()
	return &authWrap{send: send.hmac[:n], recv: recv.hmac[:n], digest: d, rh: replayHeader{when: uint32(time.Now().Unix())}}, nil
}

// wire: op | sid | hmac | pid | time | body; the HMAC covers pid | time | op | sid | body
func (a *authWrap) wrap(op byte, sid [8]byte, body []byte) []byte {
	rp := a.rh.next()
	m := hmac.New(a.digest, a.send)
	m.Write(rp)
	m.Write([]byte{op})
	m.Write(sid[:])
	m.Write(body)
	out := append([]byte{op}, sid[:]...)
	out = append(out, m.Sum(nil)...)
	out = append(out, rp...)
	return append(out, body...)
}

func (a *authWrap) unwrap(p []byte) (byte, [8]byte, []byte, error) {
	var sid [8]byte
	n := a.digest().Size()
	if len(p) < 9+n+8 {
		return 0, sid, nil, errShort
	}
	copy(sid[:], p[1:9])
	mac, rp, body := p[9:9+n], p[9+n:9+n+8], p[9+n+8:]
	m := hmac.New(a.digest, a.recv)
	m.Write(rp)
	m.Write(p[:9])
	m.Write(body)
	if subtle.ConstantTimeCompare(m.Sum(nil), mac) != 1 {
		return 0, sid, nil, errors.New("tls-auth HMAC does not match (wrong key or key-direction)")
	}
	a.rh.mu.Lock()
	fresh := a.rh.win.ok(binary.BigEndian.Uint32(rp))
	a.rh.mu.Unlock()
	if !fresh {
		return 0, sid, nil, errors.New("replayed control packet")
	}
	return p[0], sid, body, nil
}

type cryptWrap struct {
	sendKey, recvKey []byte // AES-256
	sendMAC, recvMAC []byte // HMAC-SHA256
	rh               replayHeader
}

func newCryptWrap(key []byte) *cryptWrap {
	// tls-crypt: the server uses the key in its normal direction, so a
	// client sends with slot 1
	send, recv := keyPair(key, 1)
	return &cryptWrap{sendKey: send.cipher[:32], recvKey: recv.cipher[:32], sendMAC: send.hmac[:32], recvMAC: recv.hmac[:32],
		rh: replayHeader{when: uint32(time.Now().Unix())}}
}

// wire: op | sid | pid | time | tag(32) | AES-256-CTR(body); the tag is
// HMAC-SHA256 over op | sid | pid | time | body, its first 16 bytes the IV
func (c *cryptWrap) wrap(op byte, sid [8]byte, body []byte) []byte {
	head := append(append([]byte{op}, sid[:]...), c.rh.next()...)
	m := hmac.New(sha256.New, c.sendMAC)
	m.Write(head)
	m.Write(body)
	tag := m.Sum(nil)
	blk, _ := aes.NewCipher(c.sendKey)
	enc := make([]byte, len(body))
	cipher.NewCTR(blk, tag[:16]).XORKeyStream(enc, body)
	out := append(head, tag...)
	return append(out, enc...)
}

func (c *cryptWrap) unwrap(p []byte) (byte, [8]byte, []byte, error) {
	var sid [8]byte
	if len(p) < 9+8+32 {
		return 0, sid, nil, errShort
	}
	copy(sid[:], p[1:9])
	head, tag, enc := p[:17], p[17:49], p[49:]
	blk, _ := aes.NewCipher(c.recvKey)
	body := make([]byte, len(enc))
	cipher.NewCTR(blk, tag[:16]).XORKeyStream(body, enc)
	m := hmac.New(sha256.New, c.recvMAC)
	m.Write(head)
	m.Write(body)
	if subtle.ConstantTimeCompare(m.Sum(nil), tag) != 1 {
		return 0, sid, nil, errors.New("tls-crypt authentication failed (wrong tls-crypt key?)")
	}
	c.rh.mu.Lock()
	fresh := c.rh.win.ok(binary.BigEndian.Uint32(head[9:13]))
	c.rh.mu.Unlock()
	if !fresh {
		return 0, sid, nil, errors.New("replayed control packet")
	}
	return p[0], sid, body, nil
}

// ctrlBody is a control packet's body after the wrapping.
type ctrlBody struct {
	acks      []uint32
	remoteSID [8]byte
	msgID     uint32
	payload   []byte
	hasMsg    bool
}

func encodeBody(b ctrlBody) []byte {
	out := []byte{byte(len(b.acks))}
	for _, a := range b.acks {
		out = binary.BigEndian.AppendUint32(out, a)
	}
	if len(b.acks) > 0 {
		out = append(out, b.remoteSID[:]...)
	}
	if b.hasMsg {
		out = binary.BigEndian.AppendUint32(out, b.msgID)
		out = append(out, b.payload...)
	}
	return out
}

func decodeBody(op byte, p []byte) (ctrlBody, error) {
	var b ctrlBody
	if len(p) < 1 {
		return b, errShort
	}
	n := int(p[0])
	p = p[1:]
	if len(p) < 4*n {
		return b, errShort
	}
	for i := 0; i < n; i++ {
		b.acks = append(b.acks, binary.BigEndian.Uint32(p[4*i:]))
	}
	p = p[4*n:]
	if n > 0 {
		if len(p) < 8 {
			return b, errShort
		}
		copy(b.remoteSID[:], p[:8])
		p = p[8:]
	}
	if op>>3 == opAckV1 {
		return b, nil
	}
	if len(p) < 4 {
		return b, errShort
	}
	b.hasMsg = true
	b.msgID = binary.BigEndian.Uint32(p)
	b.payload = p[4:]
	return b, nil
}
