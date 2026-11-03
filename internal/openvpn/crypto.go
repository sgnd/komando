package openvpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

var digests = map[string]func() hash.Hash{
	"SHA1": sha1.New, "SHA256": sha256.New, "SHA384": sha512.New384, "SHA512": sha512.New,
}

func supportedCipher(c string) bool {
	switch c {
	case "AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305", "AES-128-CBC", "AES-256-CBC":
		return true
	}
	return false
}

// keySlot is one direction's key material: 64 bytes for the cipher and 64
// for the HMAC (or, with an AEAD cipher, its implicit IV).
type keySlot struct{ cipher, hmac []byte }

// keyPair splits 256 bytes of key material into the two directions: with
// direction 0 (the server) slot 0 sends; the client (direction 1) sends
// with slot 1. -1 uses slot 0 both ways (tls-auth without a direction).
func keyPair(k []byte, direction int) (send, recv keySlot) {
	s0 := keySlot{k[0:64], k[64:128]}
	s1 := keySlot{k[128:192], k[192:256]}
	switch direction {
	case 0:
		return s0, s1
	case 1:
		return s1, s0
	}
	return s0, s0
}

// prf is the TLS 1.0 PRF (P_MD5 xor P_SHA1) that OpenVPN uses to derive
// keys when TLS key export is not negotiated.
func prf(secret []byte, label string, seed []byte, n int) []byte {
	half := (len(secret) + 1) / 2
	s1, s2 := secret[:half], secret[len(secret)-half:]
	ls := append([]byte(label), seed...)
	a := pHash(md5.New, s1, ls, n)
	b := pHash(sha1.New, s2, ls, n)
	for i := range a {
		a[i] ^= b[i]
	}
	return a
}

func pHash(h func() hash.Hash, secret, seed []byte, n int) []byte {
	out := make([]byte, 0, n+64)
	mac := hmac.New(h, secret)
	mac.Write(seed)
	a := mac.Sum(nil)
	for len(out) < n {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		out = append(out, mac.Sum(nil)...)
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return out[:n]
}

// dataCipher seals and opens data channel packets for one key.
type dataCipher interface {
	// seal returns the encrypted packet after the header; ad is the
	// header bytes the AEAD authenticates (P_DATA_V2's op and peer id).
	seal(pid uint32, ad, plain []byte) []byte
	open(ad, pkt []byte) (pid uint32, plain []byte, err error)
}

var errAuth = errors.New("packet authentication failed")

type aeadCipher struct {
	send, recv     cipher.AEAD
	sendIV, recvIV []byte // 8 implicit bytes each
}

func newAEAD(name string, send, recv keySlot) (dataCipher, error) {
	mk := func(k []byte) (cipher.AEAD, error) {
		switch name {
		case "CHACHA20-POLY1305":
			return chacha20poly1305.New(k[:32])
		case "AES-128-GCM":
			b, err := aes.NewCipher(k[:16])
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(b)
		default:
			b, err := aes.NewCipher(k[:32])
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(b)
		}
	}
	s, err := mk(send.cipher)
	if err != nil {
		return nil, err
	}
	r, err := mk(recv.cipher)
	if err != nil {
		return nil, err
	}
	return &aeadCipher{send: s, recv: r, sendIV: send.hmac[:8], recvIV: recv.hmac[:8]}, nil
}

// wire: packet id (4) | tag (16) | ciphertext; nonce: packet id | implicit IV
func (a *aeadCipher) seal(pid uint32, ad, plain []byte) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce, pid)
	copy(nonce[4:], a.sendIV)
	add := append(append([]byte{}, ad...), nonce[:4]...)
	ct := a.send.Seal(nil, nonce, plain, add)
	tag, body := ct[len(ct)-16:], ct[:len(ct)-16]
	out := make([]byte, 0, 4+16+len(body))
	out = append(out, nonce[:4]...)
	out = append(out, tag...)
	return append(out, body...)
}

func (a *aeadCipher) open(ad, pkt []byte) (uint32, []byte, error) {
	if len(pkt) < 4+16 {
		return 0, nil, errAuth
	}
	nonce := make([]byte, 12)
	copy(nonce, pkt[:4])
	copy(nonce[4:], a.recvIV)
	ct := append(append([]byte{}, pkt[20:]...), pkt[4:20]...)
	add := append(append([]byte{}, ad...), pkt[:4]...)
	plain, err := a.recv.Open(nil, nonce, ct, add)
	if err != nil {
		return 0, nil, errAuth
	}
	return binary.BigEndian.Uint32(pkt[:4]), plain, nil
}

type cbcCipher struct {
	send, recv       cipher.Block
	sendMAC, recvMAC []byte
	digest           func() hash.Hash
}

func newCBC(name, auth string, send, recv keySlot) (dataCipher, error) {
	n := 32
	if strings.HasPrefix(name, "AES-128") {
		n = 16
	}
	s, err := aes.NewCipher(send.cipher[:n])
	if err != nil {
		return nil, err
	}
	r, err := aes.NewCipher(recv.cipher[:n])
	if err != nil {
		return nil, err
	}
	d, ok := digests[auth]
	if !ok {
		return nil, errors.New("CBC needs an auth digest")
	}
	size := d().Size()
	return &cbcCipher{send: s, recv: r, sendMAC: send.hmac[:size], recvMAC: recv.hmac[:size], digest: d}, nil
}

// wire: HMAC | IV | ciphertext of (packet id (4) | payload), PKCS#7 padded
func (c *cbcCipher) seal(pid uint32, _, plain []byte) []byte {
	iv := make([]byte, 16)
	rand.Read(iv)
	buf := make([]byte, 4, 4+len(plain)+16)
	binary.BigEndian.PutUint32(buf, pid)
	buf = append(buf, plain...)
	pad := 16 - len(buf)%16
	for i := 0; i < pad; i++ {
		buf = append(buf, byte(pad))
	}
	cipher.NewCBCEncrypter(c.send, iv).CryptBlocks(buf, buf)
	m := hmac.New(c.digest, c.sendMAC)
	m.Write(iv)
	m.Write(buf)
	out := m.Sum(nil)
	out = append(out, iv...)
	return append(out, buf...)
}

func (c *cbcCipher) open(_, pkt []byte) (uint32, []byte, error) {
	ms := c.digest().Size()
	if len(pkt) < ms+32 || (len(pkt)-ms-16)%16 != 0 {
		return 0, nil, errAuth
	}
	m := hmac.New(c.digest, c.recvMAC)
	m.Write(pkt[ms:])
	if subtle.ConstantTimeCompare(m.Sum(nil), pkt[:ms]) != 1 {
		return 0, nil, errAuth
	}
	iv, ct := pkt[ms:ms+16], append([]byte{}, pkt[ms+16:]...)
	cipher.NewCBCDecrypter(c.recv, iv).CryptBlocks(ct, ct)
	pad := int(ct[len(ct)-1])
	if pad == 0 || pad > 16 || pad > len(ct)-4 {
		return 0, nil, errAuth
	}
	ct = ct[:len(ct)-pad]
	return binary.BigEndian.Uint32(ct[:4]), ct[4:], nil
}

func newDataCipher(name, auth string, material []byte) (dataCipher, error) {
	// the data channel keys run the other way round from tls-auth: the
	// client sends with slot 0 and the server with slot 1
	send, recv := keyPair(material, 0)
	if strings.HasSuffix(name, "-CBC") {
		return newCBC(name, auth, send, recv)
	}
	return newAEAD(name, send, recv)
}

// replay is a sliding window over received packet ids.
type replay struct {
	top  uint32
	bits uint64
	seen bool
}

func (r *replay) ok(pid uint32) bool {
	switch {
	case !r.seen || pid > r.top:
		shift := pid - r.top
		if !r.seen || shift >= 64 {
			r.bits = 0
		} else {
			r.bits <<= shift
		}
		r.bits |= 1
		r.top, r.seen = pid, true
		return true
	case r.top-pid >= 64:
		return false
	}
	bit := uint64(1) << (r.top - pid)
	if r.bits&bit != 0 {
		return false
	}
	r.bits |= bit
	return true
}
