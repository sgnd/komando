package netx

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"

	"github.com/sgnd/komando/internal/flock"
)

// A WireGuard interface key may run in one session at a time on this
// computer: two sessions with the same key take turns being the peer the
// server answers, and both break. The key lock is per user and outside any
// komando home, so it also sees sessions of other homes.

// KeyHolder is the komando process that runs a WireGuard session for one
// interface key, as the key lock records it. It never holds the private key.
type KeyHolder struct {
	PublicKey string `json:"public_key"`
	PID       int    `json:"pid"`
	ProcStart string `json:"proc_start,omitempty"` // ProcessStart of PID: a reused pid is another process
	Socks     string `json:"socks,omitempty"`
	Home      string `json:"home"`
	Vpn       string `json:"vpn"`
	// Users are the VPN entries of Home that use this session (the same
	// key); the last one's `vpn down` stops it.
	Users []string `json:"users,omitempty"`
}

// KeyLockDir is the per-user folder of key locks; tests point it elsewhere.
var KeyLockDir = func() (string, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "komando", "wireguard"), nil
}

// WGPublicKey derives the base64 public key of a base64 private key.
func WGPublicKey(private string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(private))
	if err != nil || len(b) != 32 {
		return "", errors.New("the WireGuard private key is not a key (32 bytes in base64)")
	}
	pub, err := curve25519.X25519(b, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// Alive reports whether the recorded process still runs: the same pid with
// the same start time.
func (h *KeyHolder) Alive() bool {
	if h == nil || !Alive(h.PID) {
		return false
	}
	if !startTimesKnown {
		return true
	}
	return h.ProcStart != "" && ProcessStart(h.PID) == h.ProcStart
}

// withKeyRecord runs fn with the record for pub (nil when there is none or
// it does not parse), holding the record's file lock.
func withKeyRecord(pub string, fn func(path string, cur *KeyHolder) error) error {
	dir, err := KeyLockDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(pub))
	path := filepath.Join(dir, hex.EncodeToString(sum[:12])+".json")
	lf, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := flock.Lock(lf); err != nil {
		return err
	}
	defer func() { _ = flock.Unlock(lf) }()
	var cur *KeyHolder
	if b, err := os.ReadFile(path); err == nil {
		var h KeyHolder
		if json.Unmarshal(b, &h) == nil && h.PublicKey == pub {
			cur = &h
		}
	}
	return fn(path, cur)
}

// KeyInUse is the live process holding pub, or nil.
func KeyInUse(pub string) (*KeyHolder, error) {
	var live *KeyHolder
	err := withKeyRecord(pub, func(_ string, cur *KeyHolder) error {
		if cur.Alive() {
			live = cur
		}
		return nil
	})
	return live, err
}

// ClaimKey records h as the holder of h.PublicKey. When another live
// process holds it, nothing is written and that holder is returned. A
// record whose process has ended is taken over.
func ClaimKey(h KeyHolder) (other *KeyHolder, err error) {
	err = withKeyRecord(h.PublicKey, func(path string, cur *KeyHolder) error {
		if cur.Alive() && cur.PID != h.PID {
			other = cur
			return nil
		}
		if cur != nil && cur.PID == h.PID && len(h.Users) == 0 {
			h.Users = cur.Users
		}
		if len(h.Users) == 0 {
			h.Users = []string{h.Vpn}
		}
		return writeKeyRecord(path, h)
	})
	return other, err
}

func writeKeyRecord(path string, h KeyHolder) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// EditKeyUsers changes the Users of the key record the process pid
// (started at procStart) holds; nothing when it holds none.
func EditKeyUsers(pid int, procStart string, fn func(users []string) []string) error {
	dir, err := KeyLockDir()
	if err != nil {
		return err
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, f := range files {
		var h KeyHolder
		if b, err := os.ReadFile(f); err != nil || json.Unmarshal(b, &h) != nil || h.PID != pid || h.ProcStart != procStart {
			continue
		}
		return withKeyRecord(h.PublicKey, func(path string, cur *KeyHolder) error {
			if cur == nil || cur.PID != pid || cur.ProcStart != procStart {
				return nil
			}
			cur.Users = fn(cur.Users)
			return writeKeyRecord(path, *cur)
		})
	}
	return nil
}

// ReleaseKey removes the record of pub while it is still pid's.
func ReleaseKey(pub string, pid int) error {
	return withKeyRecord(pub, func(path string, cur *KeyHolder) error {
		if cur == nil || cur.PID != pid {
			return nil
		}
		return os.Remove(path)
	})
}
