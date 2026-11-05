package ipsec

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// ESP (RFC 4303) with AES-CBC or 3DES and HMAC, or AES-GCM (RFC 4106);
// 32-bit sequence numbers and a 64-packet replay window.

const (
	nextIPv4 = 4
	nextUDP  = 17
)

type espKeys struct {
	enc   []byte
	integ []byte
	salt  []byte // GCM
}

type espSuite struct {
	c     cipherAlg
	integ integAlg // unused with GCM
}

// keyLen is how much key material the suite takes per direction.
func (s espSuite) keyLen() int {
	if s.c.gcm {
		return s.c.key + 4
	}
	return s.c.key + s.integ.key
}

func (s espSuite) split(b []byte) espKeys {
	if s.c.gcm {
		return espKeys{enc: b[:s.c.key], salt: b[s.c.key : s.c.key+4]}
	}
	return espKeys{enc: b[:s.c.key], integ: b[s.c.key : s.c.key+s.integ.key]}
}

func (s espSuite) String() string {
	if s.c.gcm {
		return s.c.name
	}
	return s.c.name + "/HMAC-" + s.integ.h.name
}

// espSA is one pair of ESP SAs (in and out).
type espSA struct {
	suite  espSuite
	spiIn  uint32
	spiOut uint32
	in     espKeys
	out    espKeys
	aeadIn cipher.AEAD
	aeadO  cipher.AEAD
	blkIn  cipher.Block
	blkOut cipher.Block

	born time.Time

	mu     sync.Mutex
	seq    uint32
	top    uint32 // highest sequence number received
	window uint64 // bit i: top-i was seen
}

func newESP(s espSuite, spiIn, spiOut uint32, in, out espKeys) (*espSA, error) {
	e := &espSA{suite: s, spiIn: spiIn, spiOut: spiOut, in: in, out: out, born: time.Now()}
	var err error
	if e.blkIn, err = s.c.block(in.enc); err != nil {
		return nil, err
	}
	if e.blkOut, err = s.c.block(out.enc); err != nil {
		return nil, err
	}
	if s.c.gcm {
		if e.aeadIn, err = cipher.NewGCM(e.blkIn); err != nil {
			return nil, err
		}
		if e.aeadO, err = cipher.NewGCM(e.blkOut); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// seal wraps one payload (an IP packet in tunnel mode, a UDP datagram in
// transport mode).
func (e *espSA) seal(next byte, payload []byte) ([]byte, error) {
	e.mu.Lock()
	e.seq++
	seq := e.seq
	e.mu.Unlock()
	if seq == 0 {
		return nil, errors.New("ESP: the sequence numbers ran out; the SA must be rekeyed")
	}
	align := 4
	if !e.suite.c.gcm {
		align = e.suite.c.blockSize()
	}
	padLen := (align - (len(payload)+2)%align) % align
	plain := make([]byte, 0, len(payload)+padLen+2)
	plain = append(plain, payload...)
	for i := 1; i <= padLen; i++ {
		plain = append(plain, byte(i))
	}
	plain = append(plain, byte(padLen), next)
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr, e.spiOut)
	binary.BigEndian.PutUint32(hdr[4:], seq)
	if e.suite.c.gcm {
		iv := make([]byte, 8)
		binary.BigEndian.PutUint64(iv, uint64(seq)) // unique per key: the sequence number
		nonce := append(append([]byte{}, e.out.salt...), iv...)
		out := append(hdr, iv...)
		return e.aeadO.Seal(out, nonce, plain, hdr), nil
	}
	bs := e.suite.c.blockSize()
	iv := random(bs)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(e.blkOut, iv).CryptBlocks(ct, plain)
	out := append(append(hdr, iv...), ct...)
	return append(out, e.suite.integ.mac(e.out.integ, out)...), nil
}

var errReplay = errors.New("ESP: replayed packet")

// open checks and unwraps one ESP packet.
func (e *espSA) open(pkt []byte) (next byte, payload []byte, err error) {
	if len(pkt) < 8 {
		return 0, nil, errors.New("ESP: short packet")
	}
	seq := binary.BigEndian.Uint32(pkt[4:])
	if !e.replayOK(seq) {
		return 0, nil, errReplay
	}
	var plain []byte
	if e.suite.c.gcm {
		if len(pkt) < 8+8+16 {
			return 0, nil, errors.New("ESP: short packet")
		}
		nonce := append(append([]byte{}, e.in.salt...), pkt[8:16]...)
		if plain, err = e.aeadIn.Open(nil, nonce, pkt[16:], pkt[:8]); err != nil {
			return 0, nil, errors.New("ESP: authentication failed")
		}
	} else {
		bs, icv := e.suite.c.blockSize(), e.suite.integ.icv
		if len(pkt) < 8+bs+bs+icv || (len(pkt)-8-bs-icv)%bs != 0 {
			return 0, nil, errors.New("ESP: bad length")
		}
		body, mac := pkt[:len(pkt)-icv], pkt[len(pkt)-icv:]
		if !hmac.Equal(mac, e.suite.integ.mac(e.in.integ, body)) {
			return 0, nil, errors.New("ESP: authentication failed")
		}
		ct := body[8+bs:]
		plain = make([]byte, len(ct))
		cipher.NewCBCDecrypter(e.blkIn, body[8:8+bs]).CryptBlocks(plain, ct)
	}
	if len(plain) < 2 {
		return 0, nil, errors.New("ESP: bad padding")
	}
	padLen := int(plain[len(plain)-2])
	if padLen+2 > len(plain) {
		return 0, nil, errors.New("ESP: bad padding")
	}
	e.replayMark(seq)
	return plain[len(plain)-1], plain[:len(plain)-2-padLen], nil
}

func (e *espSA) replayOK(seq uint32) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if seq == 0 {
		return false
	}
	if seq > e.top {
		return true
	}
	d := e.top - seq
	return d < 64 && e.window&(1<<d) == 0
}

func (e *espSA) replayMark(seq uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if seq > e.top {
		shift := seq - e.top
		if shift >= 64 {
			e.window = 0
		} else {
			e.window <<= shift
		}
		e.window |= 1
		e.top = seq
		return
	}
	e.window |= 1 << (e.top - seq)
}
