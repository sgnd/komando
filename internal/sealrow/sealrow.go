// Package sealrow seals one record of komando's local store (design:
// docs/design/sync-security.md section 16). A sealed row is
//
//	format (1 byte) | suite (1 byte) | nonce (12 bytes) | AES-256-GCM ciphertext
//
// and the sealing is bound to the row's ID, type and version, so a row
// copied to another ID, type or version, or an older version put back in
// its place, does not open. The ID, type and version stay readable in their
// own columns; everything else, names included, is inside the seal.
//
// The package holds no key and reads no file or environment: the caller
// passes a Key made once from the store's master key.
package sealrow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Format is the row format this komando writes. A row with a higher number
// was written by a newer komando.
const Format byte = 1

// SuiteAESGCM is HKDF-SHA256 to an AES-256-GCM key, random 96-bit nonces.
const SuiteAESGCM byte = 1

const (
	headerLen = 2
	nonceLen  = 12
	// MasterLen is the size of the master key a Key is made from.
	MasterLen = 32
	// hkdfInfo separates the store key from every other key made from the
	// same master key (the vault's per-secret keys).
	hkdfInfo = "komando local store v1"
)

var (
	// ErrNewerFormat: the row was written by a newer komando.
	ErrNewerFormat = errors.New("sealrow: row written by a newer komando; update komando")
	// ErrOpen: the row is damaged, was sealed with another key, or was moved
	// to another ID, type or version.
	ErrOpen = errors.New("sealrow: row does not open (wrong key, damaged, or moved)")
)

// Key seals and opens rows. It is safe for use by several goroutines.
type Key struct {
	aead cipher.AEAD
}

// NewKey makes the row key from the store's 32-byte master key.
func NewKey(master []byte) (*Key, error) {
	if len(master) != MasterLen {
		return nil, fmt.Errorf("sealrow: master key is %d bytes, want %d", len(master), MasterLen)
	}
	k, err := hkdf.Key(sha256.New, master, nil, hkdfInfo, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Key{aead: a}, nil
}

// Row names the readable columns the seal is bound to.
type Row struct {
	ID      string
	Type    string
	Version uint64
}

// aad binds the seal to the header and the row's columns. Each string is
// length-prefixed, so ("ab","c") and ("a","bc") differ.
func (r Row) aad(format, suite byte) []byte {
	b := make([]byte, 0, 2+8+len(r.ID)+8+len(r.Type)+8)
	b = append(b, format, suite)
	b = binary.BigEndian.AppendUint64(b, uint64(len(r.ID)))
	b = append(b, r.ID...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(r.Type)))
	b = append(b, r.Type...)
	return binary.BigEndian.AppendUint64(b, r.Version)
}

// Seal returns the sealed form of plain for row r.
func (k *Key) Seal(r Row, plain []byte) ([]byte, error) {
	if r.ID == "" || r.Type == "" {
		return nil, errors.New("sealrow: a row needs an ID and a type")
	}
	out := make([]byte, headerLen+nonceLen, headerLen+nonceLen+len(plain)+k.aead.Overhead())
	out[0], out[1] = Format, SuiteAESGCM
	if _, err := rand.Read(out[headerLen:]); err != nil {
		return nil, err
	}
	return k.aead.Seal(out, out[headerLen:], plain, r.aad(Format, SuiteAESGCM)), nil
}

// Open returns the plain form of a row sealed by Seal for the same r.
func (k *Key) Open(r Row, sealed []byte) ([]byte, error) {
	if len(sealed) < headerLen {
		return nil, ErrOpen
	}
	if sealed[0] > Format {
		return nil, ErrNewerFormat
	}
	if sealed[0] != Format || sealed[1] != SuiteAESGCM {
		if sealed[1] > SuiteAESGCM {
			return nil, ErrNewerFormat
		}
		return nil, ErrOpen
	}
	if len(sealed) < headerLen+nonceLen+k.aead.Overhead() {
		return nil, ErrOpen
	}
	plain, err := k.aead.Open(nil, sealed[headerLen:headerLen+nonceLen], sealed[headerLen+nonceLen:], r.aad(sealed[0], sealed[1]))
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}

// NewID returns a random 128-bit record ID as 32 hex characters. It says
// nothing about the record.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
