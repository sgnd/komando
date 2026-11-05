// Package ipsec holds komando's own IPsec clients: IKEv1 (for L2TP/IPsec
// and Cisco-style IPsec with XAUTH) and IKEv2, with ESP carried in UDP
// (RFC 3948), so they run as an ordinary program without admin rights and
// without changing the computer's network: komando always tells the server
// it is behind NAT, so ESP never needs a raw socket.
//
// Written from the RFCs (2407-2409, 3706, 3947, 3948, 4303, 7296, 7427,
// draft-beaulieu-ike-xauth, draft-dukes-ike-mode-cfg); no code from
// strongSwan, Libreswan or racoon is used.
package ipsec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// ---- Diffie-Hellman groups

type dhGroup interface {
	ID() uint16
	Public() []byte
	Shared(peer []byte) ([]byte, error)
}

func hexInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(strings.Join(strings.Fields(s), ""), 16)
	if !ok {
		panic("bad prime")
	}
	return n
}

// MODP primes: RFC 2409 6.2 (group 2), RFC 3526 (groups 5, 14).
var modpPrimes = map[uint16]*big.Int{
	2: hexInt(`FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
		EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381 FFFFFFFF FFFFFFFF`),
	5: hexInt(`FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
		EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
		83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF`),
	14: hexInt(`FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
		EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
		EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
		83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
		E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
		15728E5A 8AACAA68 FFFFFFFF FFFFFFFF`),
}

type modp struct {
	id   uint16
	p    *big.Int
	x    *big.Int
	pub  []byte
	size int
}

func newMODP(id uint16) (*modp, error) {
	p := modpPrimes[id]
	size := (p.BitLen() + 7) / 8
	xb := make([]byte, 32) // 256-bit exponent: well above the groups' strength
	if _, err := rand.Read(xb); err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(xb)
	pub := new(big.Int).Exp(big.NewInt(2), x, p)
	return &modp{id: id, p: p, x: x, pub: pub.FillBytes(make([]byte, size)), size: size}, nil
}

func (m *modp) ID() uint16     { return m.id }
func (m *modp) Public() []byte { return m.pub }
func (m *modp) Shared(peer []byte) ([]byte, error) {
	if len(peer) != m.size {
		return nil, fmt.Errorf("DH: the server's key has %d bytes, want %d", len(peer), m.size)
	}
	y := new(big.Int).SetBytes(peer)
	one := big.NewInt(1)
	if y.Cmp(one) <= 0 || y.Cmp(new(big.Int).Sub(m.p, one)) >= 0 {
		return nil, errors.New("DH: the server's key is invalid")
	}
	return new(big.Int).Exp(y, m.x, m.p).FillBytes(make([]byte, m.size)), nil
}

type ecGroup struct {
	id    uint16
	curve ecdh.Curve
	key   *ecdh.PrivateKey
}

func newEC(id uint16) (*ecGroup, error) {
	c := map[uint16]ecdh.Curve{19: ecdh.P256(), 20: ecdh.P384(), 31: ecdh.X25519()}[id]
	k, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ecGroup{id: id, curve: c, key: k}, nil
}

func (e *ecGroup) ID() uint16 { return e.id }

// Public is x|y for the NIST curves (RFC 5903: no 0x04 prefix).
func (e *ecGroup) Public() []byte {
	b := e.key.PublicKey().Bytes()
	if e.id != 31 {
		return b[1:]
	}
	return b
}

func (e *ecGroup) Shared(peer []byte) ([]byte, error) {
	if e.id != 31 {
		peer = append([]byte{4}, peer...)
	}
	pk, err := e.curve.NewPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("DH: the server's key is invalid: %v", err)
	}
	return e.key.ECDH(pk)
}

func newDH(id uint16) (dhGroup, error) {
	switch id {
	case 2, 5, 14:
		return newMODP(id)
	case 19, 20, 31:
		return newEC(id)
	}
	return nil, fmt.Errorf("DH group %d is not supported", id)
}

// ---- hashes and PRFs

type hashAlg struct {
	name string
	new  func() hash.Hash
}

var (
	hSHA1   = hashAlg{"SHA1", sha1.New}
	hSHA256 = hashAlg{"SHA256", sha256.New}
	hSHA384 = hashAlg{"SHA384", sha512.New384}
	hSHA512 = hashAlg{"SHA512", sha512.New}
)

func (h hashAlg) size() int { return h.new().Size() }

func (h hashAlg) sum(parts ...[]byte) []byte {
	x := h.new()
	for _, p := range parts {
		x.Write(p)
	}
	return x.Sum(nil)
}

func (h hashAlg) prf(key []byte, parts ...[]byte) []byte {
	m := hmac.New(h.new, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// prfPlus is IKEv2's prf+ (RFC 7296 2.13).
func (h hashAlg) prfPlus(key, seed []byte, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		t = h.prf(key, t, seed, []byte{i})
		out = append(out, t...)
	}
	return out[:n]
}

// ---- integrity (HMAC, truncated)

type integAlg struct {
	h   hashAlg
	key int // key length
	icv int // truncated length
}

func (a integAlg) mac(key []byte, parts ...[]byte) []byte { return a.h.prf(key, parts...)[:a.icv] }

var (
	integSHA1   = integAlg{hSHA1, 20, 12}
	integSHA256 = integAlg{hSHA256, 32, 16}
	integSHA384 = integAlg{hSHA384, 48, 24}
	integSHA512 = integAlg{hSHA512, 64, 32}
)

// ---- encryption

type cipherAlg struct {
	name   string
	key    int  // key length in bytes (without a GCM salt)
	gcm    bool // AES-GCM with a 16-byte ICV
	triple bool // 3DES
}

func (c cipherAlg) block(key []byte) (cipher.Block, error) {
	if c.triple {
		return des.NewTripleDESCipher(key)
	}
	return aes.NewCipher(key)
}

func (c cipherAlg) blockSize() int {
	if c.triple {
		return 8
	}
	return 16
}

var (
	aes128    = cipherAlg{name: "AES-128", key: 16}
	aes256    = cipherAlg{name: "AES-256", key: 32}
	tripleDES = cipherAlg{name: "3DES", key: 24, triple: true}
	gcm128    = cipherAlg{name: "AES-GCM-128", key: 16, gcm: true}
	gcm256    = cipherAlg{name: "AES-GCM-256", key: 32, gcm: true}
)

func cbcEncrypt(c cipherAlg, key, iv, plain []byte) ([]byte, error) {
	b, err := c.block(key)
	if err != nil {
		return nil, err
	}
	if len(plain)%b.BlockSize() != 0 {
		return nil, errors.New("CBC: not a whole number of blocks")
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(out, plain)
	return out, nil
}

func cbcDecrypt(c cipherAlg, key, iv, ct []byte) ([]byte, error) {
	b, err := c.block(key)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%b.BlockSize() != 0 {
		return nil, errors.New("CBC: not a whole number of blocks")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(out, ct)
	return out, nil
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
