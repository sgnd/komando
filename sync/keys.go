package komandosync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"sync"
)

// Signer is a P-256 key whose private half never leaves where it lives.
// On Apple devices the Secure Enclave implements it: SignMessage matches
// SecKeyCreateSignature with ecdsaSignatureMessageX962SHA256 (it hashes
// msg with SHA-256 and returns an ASN.1 DER signature). An authority key
// asks for Face ID or Touch ID inside SignMessage, every time.
type Signer interface {
	Public() *ecdsa.PublicKey
	SignMessage(msg []byte) ([]byte, error)
}

// Unwrapper is a device's X-Wing private key: it opens what was sealed to
// the device. On Apple devices it lives in the Keychain, this device only.
type Unwrapper interface {
	PublicKey() []byte
	Open(info, sealed []byte) ([]byte, error)
}

// SoftSigner is the software stand-in for a Secure Enclave key.
type SoftSigner struct {
	key *ecdsa.PrivateKey
	// Presence stands in for Face ID or Touch ID on an authority key: it
	// runs before every signature, and an error refuses it. Nil asks
	// nothing (a sync key).
	Presence func() error

	mu    sync.Mutex
	count int
}

// NewSoftSigner makes a fresh P-256 key.
func NewSoftSigner() (*SoftSigner, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SoftSigner{key: k}, nil
}

// Public returns the public half.
func (s *SoftSigner) Public() *ecdsa.PublicKey { return &s.key.PublicKey }

// SignMessage signs SHA-256(msg), after Presence agrees.
func (s *SoftSigner) SignMessage(msg []byte) ([]byte, error) {
	if s.Presence != nil {
		if err := s.Presence(); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
	h := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, s.key, h[:])
}

// Signatures counts the signatures made, so tests can count prompts.
func (s *SoftSigner) Signatures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// Sig is an ECDSA P-256 signature in the one fixed form (SS 7.2): r and s
// as 32 bytes each, with s in the lower half of the group order. The Secure
// Enclave returns DER with either s; sign() turns it into this form, and
// verifySig refuses every other form, so a signature has exactly one
// spelling.
type Sig [64]byte

var (
	p256N     = elliptic.P256().Params().N
	p256HalfN = new(big.Int).Rsh(p256N, 1)
)

// ErrBadSignature: a signature does not verify, is in the wrong form, or is
// made by a key that may not sign this.
var ErrBadSignature = errors.New("komandosync: bad signature")

func signedMessage(label string, body []byte) []byte {
	m := make([]byte, 0, len(label)+1+len(body))
	m = append(m, label...)
	m = append(m, 0)
	return append(m, body...)
}

// sign signs label || 0 || body with s and returns the fixed form.
func sign(s Signer, label string, body []byte) (Sig, error) {
	var out Sig
	der, err := s.SignMessage(signedMessage(label, body))
	if err != nil {
		return out, err
	}
	var rs struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &rs)
	if err != nil || len(rest) != 0 || rs.R == nil || rs.S == nil {
		return out, ErrBadSignature
	}
	if rs.S.Cmp(p256HalfN) > 0 {
		rs.S.Sub(p256N, rs.S)
	}
	rs.R.FillBytes(out[:32])
	rs.S.FillBytes(out[32:])
	return out, nil
}

// verifySig checks a fixed-form signature over label || 0 || body.
func verifySig(pub *ecdsa.PublicKey, label string, body []byte, sig Sig) bool {
	if pub == nil {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(p256N) >= 0 || s.Cmp(p256HalfN) > 0 {
		return false
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return false
	}
	h := sha256.Sum256(signedMessage(label, body))
	return ecdsa.VerifyASN1(pub, h[:], der)
}

// pubBytes is the uncompressed point of a P-256 key (65 bytes).
func pubBytes(p *ecdsa.PublicKey) []byte {
	b, err := p.Bytes()
	if err != nil {
		panic("komandosync: invalid P-256 public key")
	}
	return b
}

// parsePub reads an uncompressed P-256 point; nil for anything else.
func parsePub(b []byte) *ecdsa.PublicKey {
	if len(b) == 0 {
		return nil
	}
	p, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b)
	if err != nil {
		return nil
	}
	return p
}

// The HPKE suite: X-Wing (draft-ietf-hpke-pq, KEM ID 0x647a), HKDF-SHA256,
// AES-256-GCM (SS 7.2).
var (
	xwing    = hpke.MLKEM768X25519()
	hpkeKDF  = hpke.HKDFSHA256()
	hpkeAEAD = hpke.AES256GCM()
)

// xwingKEMID is the KEM ID the format names; a test checks Go agrees.
const xwingKEMID = 0x647a

type softUnwrapper struct{ k hpke.PrivateKey }

// NewSoftUnwrapper makes a fresh X-Wing key in memory.
func NewSoftUnwrapper() (Unwrapper, error) {
	k, err := xwing.GenerateKey()
	if err != nil {
		return nil, err
	}
	return softUnwrapper{k}, nil
}

func (u softUnwrapper) PublicKey() []byte { return u.k.PublicKey().Bytes() }

func (u softUnwrapper) Open(info, sealed []byte) ([]byte, error) {
	return hpke.Open(u.k, hpkeKDF, hpkeAEAD, info, sealed)
}

// sealTo seals plaintext to an X-Wing public key. info binds the result to
// its account, generation and receiver (SS 7.1).
func sealTo(pub, info, plaintext []byte) ([]byte, error) {
	pk, err := xwing.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return hpke.Seal(pk, hpkeKDF, hpkeAEAD, info, plaintext)
}

// DeviceKeys are the three keys a device makes and never lets go (SS 6.1).
type DeviceKeys struct {
	Sync Signer
	// Authority is nil on a device without Touch ID or Face ID: it can
	// sync, but its signatures never count for the list or for approvals.
	Authority Signer
	Unwrap    Unwrapper
}

// NewSoftDeviceKeys makes software keys. withAuthority false models a Mac
// without Touch ID.
func NewSoftDeviceKeys(withAuthority bool) (*DeviceKeys, error) {
	s, err := NewSoftSigner()
	if err != nil {
		return nil, err
	}
	u, err := NewSoftUnwrapper()
	if err != nil {
		return nil, err
	}
	k := &DeviceKeys{Sync: s, Unwrap: u}
	if withAuthority {
		a, err := NewSoftSigner()
		if err != nil {
			return nil, err
		}
		k.Authority = a
	}
	return k, nil
}

// DeviceRecord is what the device list holds about a device, in the clear.
// The name and SSH key sit in a sealed record; InfoHash pins it.
type DeviceRecord struct {
	SyncPub   []byte
	AuthPub   []byte // empty: no authority key
	UnwrapPub []byte
	InfoHash  Hash
}

// ID is the device's ID.
func (r *DeviceRecord) ID() DeviceID {
	var id DeviceID
	h := sum(labelDeviceID, r.SyncPub)
	copy(id[:], h[:])
	return id
}

func (r *DeviceRecord) encode(e *enc) {
	e.bytes(r.SyncPub)
	e.bytes(r.AuthPub)
	e.bytes(r.UnwrapPub)
	e.raw(r.InfoHash[:])
}

func decodeDeviceRecord(d *dec) DeviceRecord {
	var r DeviceRecord
	r.SyncPub = d.bytes()
	r.AuthPub = d.bytes()
	r.UnwrapPub = d.bytes()
	d.fixed(r.InfoHash[:])
	return r
}

func (r *DeviceRecord) bytes() []byte {
	var e enc
	r.encode(&e)
	return e.b
}

// valid checks the keys parse, so a list never holds junk.
func (r *DeviceRecord) valid() bool {
	if parsePub(r.SyncPub) == nil {
		return false
	}
	if len(r.AuthPub) != 0 && parsePub(r.AuthPub) == nil {
		return false
	}
	_, err := xwing.NewPublicKey(r.UnwrapPub)
	return err == nil
}

// infoSaltSize is the size of the salt in a device's name record.
const infoSaltSize = 16

// deviceInfoHash pins a device's sealed name record. The salt stops the
// server from confirming a guessed name ("Budi's iPhone"). sum puts each
// part's length in front, so salt and name cannot trade bytes.
func deviceInfoHash(salt []byte, name string) Hash {
	return sum(labelInfo, salt, []byte(name))
}
