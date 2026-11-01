// Package vault stores secrets (passwords, key passphrases, tokens) encrypted
// with AES-256-GCM. The key is derived with scrypt from $KOMANDO_VAULT_PASS
// when set, otherwise from a random 32-byte key file (vault.key, mode 0600).
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/sgnd/komando/internal/store"
)

type file struct {
	Version int               `json:"version"`
	Salt    []byte            `json:"salt"`
	Mode    string            `json:"mode"` // keyfile | passphrase
	Entries map[string]*entry `json:"entries"`
}

type entry struct {
	Nonce     []byte    `json:"nonce"`
	Data      []byte    `json:"data"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Info struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
}

func vaultPath() string { return store.Path("vault.json") }

func load() (*file, error) {
	if err := store.EnsureHome(); err != nil {
		return nil, err
	}
	f := &file{Version: 1, Entries: map[string]*entry{}}
	b, err := os.ReadFile(vaultPath())
	if errors.Is(err, os.ErrNotExist) {
		f.Salt = make([]byte, 16)
		_, _ = rand.Read(f.Salt)
		if os.Getenv("KOMANDO_VAULT_PASS") != "" {
			f.Mode = "passphrase"
		} else {
			f.Mode = "keyfile"
		}
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, f); err != nil {
		return nil, err
	}
	if f.Entries == nil {
		f.Entries = map[string]*entry{}
	}
	return f, nil
}

func (f *file) save() error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(vaultPath(), b, 0o600)
}

func (f *file) aead() (cipher.AEAD, error) {
	var secret []byte
	switch f.Mode {
	case "passphrase":
		p := os.Getenv("KOMANDO_VAULT_PASS")
		if p == "" {
			return nil, errors.New("vault is passphrase-protected: set KOMANDO_VAULT_PASS")
		}
		secret = []byte(p)
	default:
		kp := store.Path("vault.key")
		b, err := os.ReadFile(kp)
		if errors.Is(err, os.ErrNotExist) {
			b = make([]byte, 32)
			_, _ = rand.Read(b)
			if err := store.WriteFileAtomic(kp, b, 0o600); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
		secret = b
	}
	key, err := scrypt.Key(secret, f.Salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func Set(name, value string) error {
	f, err := load()
	if err != nil {
		return err
	}
	a, err := f.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, a.NonceSize())
	_, _ = rand.Read(nonce)
	f.Entries[name] = &entry{Nonce: nonce, Data: a.Seal(nil, nonce, []byte(value), []byte(name)), UpdatedAt: time.Now().UTC()}
	return f.save()
}

var ErrNotFound = errors.New("secret not found")

func Get(name string) (string, error) {
	f, err := load()
	if err != nil {
		return "", err
	}
	e, ok := f.Entries[name]
	if !ok {
		return "", ErrNotFound
	}
	a, err := f.aead()
	if err != nil {
		return "", err
	}
	pt, err := a.Open(nil, e.Nonce, e.Data, []byte(name))
	if err != nil {
		return "", fmt.Errorf("cannot decrypt secret %q (wrong KOMANDO_VAULT_PASS or vault.key?)", name)
	}
	return string(pt), nil
}

func Delete(name string) error {
	f, err := load()
	if err != nil {
		return err
	}
	if _, ok := f.Entries[name]; !ok {
		return ErrNotFound
	}
	delete(f.Entries, name)
	return f.save()
}

func List() ([]Info, error) {
	f, err := load()
	if err != nil {
		return nil, err
	}
	out := []Info{}
	for n, e := range f.Entries {
		out = append(out, Info{Name: n, UpdatedAt: e.UpdatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Resolve turns a reference into a value:
//
//	secret:<name>  -> vault entry
//	env:<VAR>      -> environment variable
//	file:<path>    -> file contents (trailing newline trimmed)
func Resolve(ref string) (string, error) {
	switch {
	case ref == "":
		return "", nil
	case strings.HasPrefix(ref, "secret:"):
		return Get(strings.TrimPrefix(ref, "secret:"))
	case strings.HasPrefix(ref, "env:"):
		v, ok := os.LookupEnv(strings.TrimPrefix(ref, "env:"))
		if !ok {
			return "", fmt.Errorf("environment variable %s not set", strings.TrimPrefix(ref, "env:"))
		}
		return v, nil
	case strings.HasPrefix(ref, "file:"):
		b, err := os.ReadFile(strings.TrimPrefix(ref, "file:"))
		return strings.TrimRight(string(b), "\r\n"), err
	}
	return "", fmt.Errorf("invalid secret reference %q (use secret:NAME, env:VAR or file:PATH)", ref)
}
