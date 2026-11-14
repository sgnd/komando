package komandosync

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

// ErrOpen is the one answer for a sealed thing that does not open: wrong
// key, wrong place, wrong commitment or changed bytes (SS 7.2: one failure
// answer).
var ErrOpen = errors.New("komandosync: cannot open")

// Record sealing (SS 7.2 "record encryption"):
//
//	okm    = HKDF-SHA256(secret = vault key, salt = 32 random bytes,
//	                     info = label || SHA-256(bound place), 64 bytes)
//	key    = okm[0:32]   AES-256-GCM key, used for this one write only
//	commit = okm[32:64]  key commitment tag, stored in the clear
//	nonce  = 12 zero bytes (safe: the key is never used twice)
//	ct     = AES-256-GCM(key, nonce, Padme(len || plaintext), aad = place)
//
// Why this commitment: AES-GCM alone is not key-committing; one ciphertext
// can be made to open under two keys (the "invisible salamanders" attack).
// Deriving the key and the tag from one HKDF call and checking the tag
// before opening is the CommitKey construction of Albertini, Duong, Gueron,
// Koelbl, Luykx and Schmieg (USENIX Security 2022): to make one stored tag
// fit two vault keys an attacker needs an HMAC-SHA256 collision on 256
// output bits. Because the place goes into info, the tag also commits to
// the place. It costs one HKDF call and 32 bytes per write, and needs
// nothing outside the standard library.
const (
	seedSize   = 32
	commitSize = 32
)

func recordKeys(secret, seed, place []byte) (key, commit []byte) {
	ph := sha256.Sum256(place)
	okm, err := hkdf.Key(sha256.New, secret, seed, labelRecord+"\x00"+string(ph[:]), 64)
	if err != nil {
		panic(err)
	}
	return okm[:32], okm[32:]
}

func gcmWithKey(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return g
}

var zeroNonce [12]byte

// sealed is one sealed body with its seed and commitment.
type sealed struct {
	Seed   [seedSize]byte
	Commit [commitSize]byte
	CT     []byte
}

// sealRecord seals plaintext under secret, bound to place.
func sealRecord(secret, place, plaintext []byte) (sealed, error) {
	var s sealed
	if _, err := rand.Read(s.Seed[:]); err != nil {
		return s, err
	}
	return sealRecordSeed(secret, place, plaintext, s.Seed), nil
}

// sealRecordSeed is sealRecord with a given seed (test vectors).
func sealRecordSeed(secret, place, plaintext []byte, seed [seedSize]byte) sealed {
	s := sealed{Seed: seed}
	key, commit := recordKeys(secret, s.Seed[:], place)
	copy(s.Commit[:], commit)
	s.CT = gcmWithKey(key).Seal(nil, zeroNonce[:], pad(plaintext), place)
	return s
}

// openRecord checks the commitment, then opens.
func openRecord(secret, place []byte, s sealed) ([]byte, error) {
	key, commit := recordKeys(secret, s.Seed[:], place)
	if subtle.ConstantTimeCompare(commit, s.Commit[:]) != 1 {
		return nil, ErrOpen
	}
	p, err := gcmWithKey(key).Open(nil, zeroNonce[:], s.CT, place)
	if err != nil {
		return nil, ErrOpen
	}
	return unpad(p)
}

func (s *sealed) encode(e *enc) {
	e.raw(s.Seed[:])
	e.raw(s.Commit[:])
	e.bytes(s.CT)
}

func decodeSealed(d *dec) sealed {
	var s sealed
	d.fixed(s.Seed[:])
	d.fixed(s.Commit[:])
	s.CT = d.bytes()
	return s
}

func (s *sealed) bytes() []byte {
	var e enc
	s.encode(&e)
	return e.b
}

func parseSealed(b []byte) (sealed, error) {
	d := dec{b: b}
	s := decodeSealed(&d)
	return s, d.done()
}

// padme is the Padmé length (Nikitin et al., PETS 2019): at most about 12%
// larger, and it leaks O(log log L) bits of the length.
func padme(l int) int {
	if l < 2 {
		return l
	}
	e := bits.Len(uint(l)) - 1
	s := bits.Len(uint(e))
	last := e - s
	mask := 1<<last - 1
	return (l + mask) &^ mask
}

// pad writes a 4-byte length, the plaintext and zeros up to the Padmé
// length.
func pad(p []byte) []byte {
	n := padme(4 + len(p))
	out := make([]byte, n)
	binary.BigEndian.PutUint32(out, uint32(len(p)))
	copy(out[4:], p)
	return out
}

func unpad(p []byte) ([]byte, error) {
	if len(p) < 4 {
		return nil, ErrOpen
	}
	n := binary.BigEndian.Uint32(p)
	if uint64(n) > uint64(len(p)-4) || padme(4+int(n)) != len(p) {
		return nil, ErrOpen
	}
	for _, b := range p[4+n:] {
		if b != 0 {
			return nil, ErrOpen
		}
	}
	return p[4 : 4+n], nil
}

// keyID names an account key generation in the signed list without
// revealing the key.
func keyID(accountKey []byte) [16]byte {
	var id [16]byte
	h := sum(labelKeyID, accountKey)
	copy(id[:], h[:])
	return id
}

// oneTimeBox seals with a key that is used once (pairing messages), so the
// zero nonce is safe.
func oneTimeBox(key, aad, plaintext []byte) []byte {
	return gcmWithKey(key).Seal(nil, zeroNonce[:], plaintext, aad)
}

func oneTimeOpen(key, aad, box []byte) ([]byte, error) {
	p, err := gcmWithKey(key).Open(nil, zeroNonce[:], box, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return p, nil
}

func derive(secret []byte, label string, n int) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, label, n)
	if err != nil {
		panic(err)
	}
	return k
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
