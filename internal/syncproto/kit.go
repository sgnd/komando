package syncproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
)

// Kit is a recovery kit: 256 random bits (SS 6.4). The kit's signing key
// (P-256) and sealing key (X-Wing) are derived from it, so the paper holds
// one key and nothing else.
type Kit struct {
	key  [32]byte
	sign *ecdsa.PrivateKey
	seal hpke.PrivateKey
}

// NewKit makes a fresh recovery key.
func NewKit() (*Kit, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return nil, err
	}
	return KitFromKey(k)
}

// KitFromKey derives the kit's keys from its 256 bits.
func KitFromKey(key [32]byte) (*Kit, error) {
	sk, err := deriveP256(key[:], labelKitSign)
	if err != nil {
		return nil, err
	}
	seal, err := xwing.DeriveKeyPair(derive(key[:], labelKitSeal, 32))
	if err != nil {
		return nil, err
	}
	return &Kit{key: key, sign: sk, seal: seal}, nil
}

// deriveP256 turns a secret into a P-256 private key: HKDF output, tried
// again with the next counter in the rare case it is not below the order.
func deriveP256(secret []byte, label string) (*ecdsa.PrivateKey, error) {
	for i := range 64 {
		d := derive(secret, fmt.Sprintf("%s %d", label, i), 32)
		if k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d); err == nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("syncproto: cannot derive a signing key")
}

// Record is the kit as the device list holds it.
func (k *Kit) Record() KitRecord {
	return KitRecord{SignPub: pubBytes(&k.sign.PublicKey), SealPub: k.seal.PublicKey().Bytes()}
}

type kitSigner struct{ k *ecdsa.PrivateKey }

func (s kitSigner) Public() *ecdsa.PublicKey { return &s.k.PublicKey }

func (s kitSigner) SignMessage(msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, s.k, h[:])
}

func (k *Kit) signer() Signer { return kitSigner{k.sign} }

func (k *Kit) open(info, sealed []byte) ([]byte, error) {
	return hpke.Open(k.seal, hpkeKDF, hpkeAEAD, info, sealed)
}

// The letters: Crockford's base32 (digits and capitals without I, L, O
// and U), read back with O as 0 and I or L as 1, in groups of four.
const alphabet32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func encode32(b []byte) string {
	var sb strings.Builder
	var acc uint32
	n := 0
	for _, c := range b {
		acc = acc<<8 | uint32(c)
		n += 8
		for n >= 5 {
			sb.WriteByte(alphabet32[acc>>(n-5)&31])
			n -= 5
		}
	}
	if n > 0 {
		sb.WriteByte(alphabet32[acc<<(5-n)&31])
	}
	return sb.String()
}

func normalize32(s string) string {
	r := strings.NewReplacer(" ", "", "-", "", "\t", "", "\n", "", "O", "0", "I", "1", "L", "1")
	return r.Replace(strings.ToUpper(s))
}

// decode32 reads exactly nbytes; the unused low bits must be zero.
func decode32(s string, nbytes int) ([]byte, error) {
	s = normalize32(s)
	if len(s) != (nbytes*8+4)/5 {
		return nil, ErrKitTypo
	}
	out := make([]byte, 0, nbytes)
	var acc uint32
	n := 0
	for i := range len(s) {
		v := strings.IndexByte(alphabet32, s[i])
		if v < 0 {
			return nil, ErrKitTypo
		}
		acc = acc<<5 | uint32(v)
		n += 5
		if n >= 8 {
			out = append(out, byte(acc>>(n-8)))
			n -= 8
		}
	}
	if acc&(1<<n-1) != 0 {
		return nil, ErrKitTypo
	}
	return out, nil
}

func groups(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), " ")
}

// checked returns payload || the first n bytes of its labelled hash.
func checked(label string, payload []byte, n int) []byte {
	h := sum(label, payload)
	return append(append([]byte{}, payload...), h[:n]...)
}

func unchecked(label string, b []byte, n int) ([]byte, bool) {
	payload := b[:len(b)-n]
	h := sum(label, payload)
	return payload, subtle.ConstantTimeCompare(h[:n], b[len(b)-n:]) == 1
}

// Letters is the kit as printed: the key and a 3-byte check, 56 letters
// and digits in 14 groups of four.
func (k *Kit) Letters() string {
	return groups(encode32(checked(labelKitCheck, k.key[:], 3)))
}

// ParseKit reads printed letters back. A typo is caught by the check.
func ParseKit(letters string) (*Kit, error) {
	b, err := decode32(letters, 35)
	if err != nil {
		return nil, err
	}
	key, ok := unchecked(labelKitCheck, b, 3)
	if !ok {
		return nil, ErrKitTypo
	}
	return KitFromKey([32]byte(key))
}

// Challenge names the two groups of Letters the person types back before
// sync starts (spec 5.4: "a few characters are typed back").
func (k *Kit) Challenge() [2]int {
	h := sum(labelKitCheck, []byte("challenge"), k.key[:])
	a := int(h[0]) % 14
	b := int(h[1]) % 13
	if b >= a {
		b++
	}
	return [2]int{a, b}
}

// CheckTyped reports whether answers match the challenged groups.
func (k *Kit) CheckTyped(answers [2]string) bool {
	g := strings.Fields(k.Letters())
	c := k.Challenge()
	ok := 1
	for i, idx := range c {
		ok &= subtle.ConstantTimeCompare([]byte(g[idx]), []byte(normalize32(answers[i])))
	}
	return ok == 1
}

// Paper splits the kit into three parts, any two of which give it back
// (spec 5.4: the 2-of-3 paper kit). Each part is 60 letters: its number,
// a 2-byte kit ID (so parts of two kits are never mixed), its share of the
// key, and a 2-byte check.
func (k *Kit) Paper() ([3]string, error) {
	var out [3]string
	shares, err := shamirSplit(k.key[:], 3, 2)
	if err != nil {
		return out, err
	}
	id := k.paperID()
	for i, s := range shares {
		payload := append([]byte{byte(i + 1), id[0], id[1]}, s...)
		out[i] = groups(encode32(checked(labelShareCheck, payload, 2)))
	}
	return out, nil
}

// paperID names the kit on its paper parts: 16 bits of a labelled hash of
// the key, enough to tell two kits apart, too few to help a guesser.
func (k *Kit) paperID() [2]byte {
	h := sum(labelKitID, k.key[:])
	return [2]byte{h[0], h[1]}
}

const paperPartBytes = 1 + 2 + 32 + 2

type paperPart struct {
	x     byte
	id    [2]byte
	share []byte
}

// KitFromPaper puts a kit back together from two or three parts. Parts of
// another kit (an old paper kit kept by mistake) are left out; any two
// parts of one kit are enough, and the result is checked against the kit
// ID they carry.
func KitFromPaper(parts ...string) (*Kit, error) {
	var ps []paperPart
	for _, p := range parts {
		b, err := decode32(p, paperPartBytes)
		if err != nil {
			return nil, err
		}
		payload, ok := unchecked(labelShareCheck, b, 2)
		if !ok {
			return nil, ErrKitTypo
		}
		ps = append(ps, paperPart{x: payload[0], id: [2]byte(payload[1:3]), share: payload[3:]})
	}
	for i := range ps {
		for j := i + 1; j < len(ps); j++ {
			if ps[i].id != ps[j].id || ps[i].x == ps[j].x {
				continue
			}
			key, err := shamirCombine([]byte{ps[i].x, ps[j].x}, [][]byte{ps[i].share, ps[j].share})
			if err != nil {
				return nil, err
			}
			k, err := KitFromKey([32]byte(key))
			if err != nil {
				return nil, err
			}
			if k.paperID() == ps[i].id {
				return k, nil
			}
		}
	}
	return nil, ErrKitParts
}
