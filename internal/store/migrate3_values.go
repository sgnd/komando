package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/sgnd/komando/internal/sealkey"
)

// valueCipher opens and seals a secret value bound to its name: the value
// key from the master key, AES-256-GCM, the name as additional data. It is
// the vault's scheme (vault.vaultAEADFrom; TestValueKeyScheme there pins
// it), so the migration moves a value to a new name without the vault.
type valueCipher struct{ a cipher.AEAD }

func newValueCipher(master []byte) (*valueCipher, error) {
	k, err := sealkey.Derive(master, sealkey.Values)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &valueCipher{a}, nil
}

// open returns the value sealed under name; the caller clears it.
func (c *valueCipher) open(name string, v SealedValue) ([]byte, error) {
	return c.a.Open(nil, v.Nonce, v.Data, []byte(name))
}

func (c *valueCipher) seal(name string, plain []byte) (SealedValue, error) {
	nonce := make([]byte, c.a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return SealedValue{}, err
	}
	return SealedValue{Nonce: nonce, Data: c.a.Seal(nil, nonce, plain, []byte(name))}, nil
}

// rename seals the value under name from again under name to.
func (c *valueCipher) rename(from, to string, v SealedValue) (SealedValue, error) {
	plain, err := c.open(from, v)
	if err != nil {
		return SealedValue{}, err
	}
	defer clear(plain)
	return c.seal(to, plain)
}
