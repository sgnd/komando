// Package sealfile is the sealed file of `komando export --sealed` and
// `komando export --for-phone`: one format, opened with a passphrase or
// with the private key of a phone. docs/design/sealed-file.md describes
// the bytes; the iPhone app reads the same file.
//
// A file is:
//
//	magic       8 bytes   "KMDSEAL1"
//	header_len  4 bytes   little endian
//	header      header_len bytes of JSON, in the clear
//	passphrase: nonce 12 bytes, then AES-256-GCM(key, nonce, deflate(content), aad)
//	recipient:  the HPKE ciphertext of deflate(content) (enc is in the header)
//
// aad is the first 12+header_len bytes of the file (magic, header_len and
// header), so a change to the header breaks the seal.
package sealfile

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Magic starts every sealed file.
const Magic = "KMDSEAL1"

// The modes a file is opened in.
const (
	ModePassphrase = "passphrase"
	ModeRecipient  = "recipient"
)

// Suite is the recipient mode's HPKE suite (RFC 9180): DHKEM(X25519,
// HKDF-SHA256), HKDF-SHA256, AES-256-GCM. CryptoKit calls it
// Curve25519_SHA256_AES_GCM_256.
const Suite = "X25519-SHA256-AES256GCM"

// Info is the HPKE info string of the recipient mode.
const Info = "komando sealed file v1"

// The passphrase mode's scrypt cost, the same as the store's.
const (
	ScryptN = 1 << 17
	ScryptR = 8
	ScryptP = 1
)

const (
	saltLen      = 32
	nonceLen     = 12
	maxHeader    = 64 << 10
	maxContent   = 256 << 20 // what a file may unpack to: a few MB is a big export
	maxScryptN   = 1 << 20
	minScryptN   = 1 << 14
	headerPrefix = len(Magic) + 4
)

// Errors Open gives. A passphrase that does not open the file and a file
// changed after sealing look the same to AES-GCM: both are
// ErrWrongPassphrase.
var (
	ErrNotSealed       = errors.New("not a komando sealed file")
	ErrInvalid         = errors.New("the sealed file is damaged or cut short")
	ErrUnsupported     = errors.New("the sealed file uses a version or method this komando does not know")
	ErrWrongPassphrase = errors.New("the passphrase does not open the file, or the file was changed after sealing")
	ErrWrongKey        = errors.New("the file is sealed to another key")
	ErrTampered        = errors.New("the file was changed after sealing")
	ErrWrongMode       = errors.New("the file is sealed in the other mode")
)

// Header is the clear part of a file. Its fields are in the order the
// file has them.
type Header struct {
	V           int    `json:"v"`
	Mode        string `json:"mode"`
	KDF         *KDF   `json:"kdf"`
	KEM         *KEM   `json:"kem"`
	Compression string `json:"compression"`
	CreatedAt   string `json:"created_at"`
	MadeBy      string `json:"made_by"`
}

// KDF is how the passphrase mode makes its key.
type KDF struct {
	Name string `json:"name"` // scrypt
	N    int    `json:"n"`
	R    int    `json:"r"`
	P    int    `json:"p"`
	Salt string `json:"salt"` // base64, 32 bytes
}

// KEM is how the recipient mode reaches its key.
type KEM struct {
	Suite string `json:"suite"`
	Enc   string `json:"enc"`    // base64: HPKE's encapsulated key
	KeyID string `json:"key_id"` // hex SHA-256 of the recipient's public key
}

// Made is what the header says about who made the file and when.
type Made struct {
	By string    // "komando 0.14.0"
	At time.Time // the file's created_at
}

// KeyID is the key_id of a recipient's public key: the hex SHA-256 of its
// 32 bytes, which the phone shows for the person to type.
func KeyID(pub []byte) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:])
}

// IsSealed reports whether b starts like a sealed file.
func IsSealed(b []byte) bool { return bytes.HasPrefix(b, []byte(Magic)) }

// SealPassphrase seals content with a passphrase.
func SealPassphrase(content []byte, pass string, m Made) ([]byte, error) {
	if pass == "" {
		return nil, errors.New("sealfile: empty passphrase")
	}
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	h := newHeader(ModePassphrase, m)
	h.KDF = &KDF{Name: "scrypt", N: ScryptN, R: ScryptR, P: ScryptP, Salt: base64.StdEncoding.EncodeToString(salt)}
	gcm, err := passGCM(pass, h.KDF)
	if err != nil {
		return nil, err
	}
	head, err := encodeHead(h)
	if err != nil {
		return nil, err
	}
	z, err := deflate(content)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(head)+nonceLen+len(z)+gcm.Overhead())
	out = append(append(out, head...), nonce...)
	return gcm.Seal(out, nonce, z, head), nil
}

// SealRecipient seals content to a recipient's X25519 public key (32
// bytes) with HPKE base mode.
func SealRecipient(content, pub []byte, m Made) ([]byte, error) {
	pk, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("sealfile: the recipient's key: %w", err)
	}
	hpk, err := hpke.NewDHKEMPublicKey(pk)
	if err != nil {
		return nil, err
	}
	enc, s, err := hpke.NewSender(hpk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(Info))
	if err != nil {
		return nil, err
	}
	h := newHeader(ModeRecipient, m)
	h.KEM = &KEM{Suite: Suite, Enc: base64.StdEncoding.EncodeToString(enc), KeyID: KeyID(pub)}
	head, err := encodeHead(h)
	if err != nil {
		return nil, err
	}
	z, err := deflate(content)
	if err != nil {
		return nil, err
	}
	ct, err := s.Seal(head, z)
	if err != nil {
		return nil, err
	}
	return append(head, ct...), nil
}

// ReadHeader reads the clear header of a file, checked for shape only:
// nothing in it is trusted until the file opens.
func ReadHeader(file []byte) (Header, error) {
	h, _, err := splitFile(file)
	return h, err
}

// OpenPassphrase opens a passphrase file and returns its content.
func OpenPassphrase(file []byte, pass string) ([]byte, Header, error) {
	h, n, err := splitFile(file)
	if err != nil {
		return nil, h, err
	}
	if h.Mode != ModePassphrase {
		return nil, h, ErrWrongMode
	}
	body := file[n:]
	if len(body) < nonceLen+16 {
		return nil, h, ErrInvalid
	}
	gcm, err := passGCM(pass, h.KDF)
	if err != nil {
		return nil, h, err
	}
	z, err := gcm.Open(nil, body[:nonceLen], body[nonceLen:], file[:n])
	if err != nil {
		return nil, h, ErrWrongPassphrase
	}
	c, err := inflate(z)
	return c, h, err
}

// OpenRecipient opens a recipient file with the X25519 private key (32
// bytes) whose public key it was sealed to.
func OpenRecipient(file, priv []byte) ([]byte, Header, error) {
	h, n, err := splitFile(file)
	if err != nil {
		return nil, h, err
	}
	if h.Mode != ModeRecipient {
		return nil, h, ErrWrongMode
	}
	sk, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, h, fmt.Errorf("sealfile: the private key: %w", err)
	}
	if KeyID(sk.PublicKey().Bytes()) != h.KEM.KeyID {
		return nil, h, ErrWrongKey
	}
	enc, err := base64.StdEncoding.DecodeString(h.KEM.Enc)
	if err != nil {
		return nil, h, ErrInvalid
	}
	hsk, err := hpke.NewDHKEMPrivateKey(sk)
	if err != nil {
		return nil, h, err
	}
	r, err := hpke.NewRecipient(enc, hsk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(Info))
	if err != nil {
		return nil, h, ErrTampered // enc is not a point of the curve
	}
	z, err := r.Open(file[:n], file[n:])
	if err != nil {
		return nil, h, ErrTampered
	}
	c, err := inflate(z)
	return c, h, err
}

func newHeader(mode string, m Made) Header {
	at := m.At
	if at.IsZero() {
		at = time.Now()
	}
	return Header{V: 1, Mode: mode, Compression: "deflate", CreatedAt: at.UTC().Format(time.RFC3339), MadeBy: m.By}
}

// encodeHead is magic, header_len and the header: the start of the file,
// and the aad.
func encodeHead(h Header) ([]byte, error) {
	j, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	b := make([]byte, headerPrefix, headerPrefix+len(j)+64)
	copy(b, Magic)
	binary.LittleEndian.PutUint32(b[len(Magic):], uint32(len(j)))
	return append(b, j...), nil
}

// splitFile reads and checks the header; n is where the body starts.
func splitFile(file []byte) (Header, int, error) {
	var h Header
	if !IsSealed(file) {
		return h, 0, ErrNotSealed
	}
	if len(file) < headerPrefix {
		return h, 0, ErrInvalid
	}
	hl := binary.LittleEndian.Uint32(file[len(Magic):])
	if hl == 0 || hl > maxHeader || uint64(len(file)) < uint64(headerPrefix)+uint64(hl) {
		return h, 0, ErrInvalid
	}
	n := headerPrefix + int(hl)
	d := json.NewDecoder(bytes.NewReader(file[headerPrefix:n]))
	if err := d.Decode(&h); err != nil || d.More() {
		return h, 0, ErrInvalid
	}
	if h.V != 1 {
		return h, 0, ErrUnsupported
	}
	if h.Compression != "deflate" {
		return h, 0, ErrUnsupported
	}
	switch h.Mode {
	case ModePassphrase:
		if h.KDF == nil || h.KEM != nil {
			return h, 0, ErrInvalid
		}
		if h.KDF.Name != "scrypt" {
			return h, 0, ErrUnsupported
		}
	case ModeRecipient:
		if h.KEM == nil || h.KDF != nil {
			return h, 0, ErrInvalid
		}
		if h.KEM.Suite != Suite {
			return h, 0, ErrUnsupported
		}
	default:
		return h, 0, ErrUnsupported
	}
	return h, n, nil
}

// passGCM is the passphrase mode's AES-256-GCM, its key from scrypt with
// the header's settings (within limits, so a file cannot ask for gigabytes
// of memory).
func passGCM(pass string, k *KDF) (cipher.AEAD, error) {
	salt, err := base64.StdEncoding.DecodeString(k.Salt)
	if err != nil || len(salt) < 16 {
		return nil, ErrInvalid
	}
	if k.N < minScryptN || k.N > maxScryptN || k.N&(k.N-1) != 0 || k.R < 1 || k.R > 32 || k.P < 1 || k.P > 4 {
		return nil, ErrUnsupported
	}
	key, err := scrypt.Key([]byte(pass), salt, k.N, k.R, k.P, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// deflate is raw DEFLATE (RFC 1951), no zlib or gzip wrapper.
func deflate(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func inflate(z []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(z))
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxContent+1))
	if err != nil || len(b) > maxContent {
		return nil, ErrInvalid
	}
	return b, nil
}
