package ppp

import (
	"crypto/des"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf16"

	//lint:ignore SA1019 MS-CHAPv2 is defined over MD4 (RFC 2759); there is no other choice
	"golang.org/x/crypto/md4"
)

// MS-CHAPv2 (RFC 2759), shared by PPP (L2TP) and EAP-MSCHAPv2 (IKEv2).

// MSCHAPv2 is one MS-CHAPv2 answer.
type MSCHAPv2 struct {
	PeerChallenge [16]byte
	NTResponse    [24]byte
	ntHash        [16]byte
	authChallenge []byte
	user          string
}

func ntPasswordHash(password string) [16]byte {
	u := utf16.Encode([]rune(password))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	h := md4.New()
	h.Write(b)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func challengeHash(peer, auth []byte, user string) []byte {
	// the user name without a domain (RFC 2759 8.2)
	if i := strings.LastIndexByte(user, '\\'); i >= 0 {
		user = user[i+1:]
	}
	h := sha1.New()
	h.Write(peer)
	h.Write(auth)
	h.Write([]byte(user))
	return h.Sum(nil)[:8]
}

// desKey spreads 7 bytes over the 8 bytes of a DES key.
func desKey(k []byte) []byte {
	return []byte{
		k[0] & 0xfe,
		(k[0]<<7 | k[1]>>1) & 0xfe,
		(k[1]<<6 | k[2]>>2) & 0xfe,
		(k[2]<<5 | k[3]>>3) & 0xfe,
		(k[3]<<4 | k[4]>>4) & 0xfe,
		(k[4]<<3 | k[5]>>5) & 0xfe,
		(k[5]<<2 | k[6]>>6) & 0xfe,
		k[6] << 1,
	}
}

func challengeResponse(challenge []byte, hash [16]byte) [24]byte {
	var z [21]byte
	copy(z[:], hash[:])
	var out [24]byte
	for i := 0; i < 3; i++ {
		c, _ := des.NewCipher(desKey(z[7*i : 7*i+7]))
		c.Encrypt(out[8*i:], challenge)
	}
	return out
}

// NewMSCHAPv2 answers an authenticator challenge (16 bytes) with a
// random peer challenge.
func NewMSCHAPv2(authChallenge []byte, user, password string, peerChallenge [16]byte) (*MSCHAPv2, error) {
	if len(authChallenge) != 16 {
		return nil, errors.New("MS-CHAPv2: the challenge is not 16 bytes")
	}
	m := &MSCHAPv2{PeerChallenge: peerChallenge, ntHash: ntPasswordHash(password),
		authChallenge: append([]byte{}, authChallenge...), user: user}
	m.NTResponse = challengeResponse(challengeHash(peerChallenge[:], authChallenge, user), m.ntHash)
	return m, nil
}

var (
	magic1 = []byte("Magic server to client signing constant")
	magic2 = []byte("Pad to make it do more than one iteration")
)

// authenticatorResponse is the "S=..." the server must send back; it
// proves the server knows the password too.
func (m *MSCHAPv2) authenticatorResponse() string {
	hh := md4.New()
	hh.Write(m.ntHash[:])
	hashHash := hh.Sum(nil)
	h := sha1.New()
	h.Write(hashHash)
	h.Write(m.NTResponse[:])
	h.Write(magic1)
	d := h.Sum(nil)
	h = sha1.New()
	h.Write(d)
	h.Write(challengeHash(m.PeerChallenge[:], m.authChallenge, m.user))
	h.Write(magic2)
	return "S=" + strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// VerifySuccess checks the server's success message ("S=<40 hex> M=...").
func (m *MSCHAPv2) VerifySuccess(msg []byte) error {
	s := string(msg)
	if len(s) < 42 || subtle.ConstantTimeCompare([]byte(strings.ToUpper(s[:42])), []byte(m.authenticatorResponse())) != 1 {
		return errors.New("MS-CHAPv2: the server did not prove it knows the password (wrong server?)")
	}
	return nil
}

var (
	shsPad1 = make([]byte, 40)
	shsPad2 = func() []byte {
		b := make([]byte, 40)
		for i := range b {
			b[i] = 0xf2
		}
		return b
	}()
	mkMagic1 = []byte("This is the MPPE Master Key")
	mkMagic2 = []byte("On the client side, this is the send key; on the server side, it is the receive key.")
	mkMagic3 = []byte("On the client side, this is the receive key; on the server side, it is the send key.")
)

// MSK is the EAP-MSCHAPv2 master session key (RFC 3079 keys, the
// server's receive key first), used for the IKEv2 AUTH payload.
func (m *MSCHAPv2) MSK() []byte {
	hh := md4.New()
	hh.Write(m.ntHash[:])
	hashHash := hh.Sum(nil)
	h := sha1.New()
	h.Write(hashHash)
	h.Write(m.NTResponse[:])
	h.Write(mkMagic1)
	master := h.Sum(nil)[:16]
	key := func(magic []byte) []byte {
		h := sha1.New()
		h.Write(master)
		h.Write(shsPad1)
		h.Write(magic)
		h.Write(shsPad2)
		return h.Sum(nil)[:16]
	}
	// the server's receive key is the client's send key (magic 2)
	return append(key(mkMagic2), key(mkMagic3)...)
}
