package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/sgnd/komando/internal/sealdb"
)

// runtime.json's mark ties it to store.db (C115). store.db keeps a random
// mark in a sealed row, runtime.json keeps the same value, and a
// runtime.json whose mark differs is read as empty, like a plain one. The
// mark changes whenever a VPN session or a held login changes, so an old
// copy of runtime.json put back no longer opens; putting back an old
// store.db with it is the store's own old-copy check (generation.go). A
// change of last_used alone, or of jobs and tunnels, keeps the mark, so
// marking a VPN used never writes store.db. A home from before marks has
// none in either file: the empty mark, and they match.

const (
	kindRuntimeMark = "runtime"
	runtimeMarkID   = "runtime-mark"
)

// readRuntimeMark is store.db's mark, or "" when it has none.
func readRuntimeMark(tx *sealdb.Tx) (string, error) {
	r, err := tx.Get(runtimeMarkID)
	if errors.Is(err, sealdb.ErrNotFound) || err == nil && r.Deleted {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(r.Data), nil
}

// storeRuntimeMark is store.db's mark, read on its own (ReadRuntime),
// with the copy of carried runtime records written under it, if any.
func storeRuntimeMark() (string, *runtimeCopy, error) {
	d, err := DB(false)
	if errors.Is(err, ErrNoStore) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	var m string
	var c *runtimeCopy
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		if m, err = readRuntimeMark(tx); err != nil {
			return err
		}
		c, err = readRuntimeCopy(tx, m)
		return err
	})
	return m, c, err
}

// putRuntimeMark writes a new mark into store.db and returns it.
func putRuntimeMark(tx *sealdb.Tx) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	m := hex.EncodeToString(b)
	_, err := tx.Put(kindRuntimeMark, runtimeMarkID, []byte(m))
	return m, err
}

// newRuntimeMark writes a new mark into this home's store (making it on a
// fresh home) in a write step of its own.
func newRuntimeMark() (string, error) {
	d, err := DB(true)
	if err != nil {
		return "", storeErr(err)
	}
	var m string
	err = d.Update(context.Background(), func(tx *sealdb.Tx) error {
		m, err = putRuntimeMark(tx)
		return err
	})
	return m, err
}

// sessionPrint is what of the runtime data the mark follows: the VPN
// sessions without last_used, and the held logins.
func (r *Runtime) sessionPrint() ([]byte, error) {
	sessions := map[string]VpnSession{}
	for k, s := range r.Sessions {
		if s != nil {
			c := *s
			c.LastUsed = time.Time{}
			sessions[k] = c
		}
	}
	return json.Marshal(struct {
		S map[string]VpnSession `json:"s"`
		L map[string]*SSHLogin  `json:"l"`
	}{sessions, r.Logins})
}
