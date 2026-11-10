package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealrow"
)

// The sealed store (docs/design/phase0-s6.md): one SQLite file, store.db,
// whose records are sealed. A home uses it, or the files of before, by
// what is in the home folder and nothing else.

// StoreFile is the sealed store's file name in the home folder.
const StoreFile = "store.db"

// storeLock keeps two komando processes from making a fresh store at once
// (each with its own key).
const storeLock = ".store.lock"

// freshSealed makes a fresh home use the sealed store. It is off until the
// whole store can live there (S6 commit 9); tests turn it on.
var freshSealed = false

// legacyFiles are files only the file backend writes. vault.key alone does
// not count: the sealed store's key file has its own name.
var legacyFiles = []string{"state.json", "vault.json", "known_hosts", "audit.jsonl"}

// Sealed reports whether this home keeps its data in the sealed store:
// store.db is there, or the home has none of the files of before and new
// homes are sealed.
func Sealed() bool {
	if _, err := os.Stat(Path(StoreFile)); err == nil {
		return true
	}
	if !freshSealed {
		return false
	}
	return !hasLegacyFiles()
}

// MixedHome reports a home with store.db and files of before beside it
// (an older komando wrote there); doctor warns about it.
func MixedHome() bool {
	_, err := os.Stat(Path(StoreFile))
	return err == nil && hasLegacyFiles()
}

func hasLegacyFiles() bool {
	for _, f := range legacyFiles {
		if _, err := os.Stat(Path(f)); err == nil {
			return true
		}
	}
	keys, _ := filepath.Glob(Path("keys", "*"))
	return len(keys) > 0
}

// KeySource gives the store's 32-byte master key. meta holds the store's
// readable settings (key_mode, salt, ...); with create, there is no store
// yet and KeySource picks the mode and returns the settings to keep. The
// vault package sets it (it owns the keychain, key file and passphrase).
var KeySource func(meta map[string]string, create bool) (master []byte, newMeta map[string]string, err error)

// ErrNoStore: a read of a fresh home, which has no store yet. Callers
// treat it as empty.
var ErrNoStore = errors.New("store: no store yet")

var (
	dbMu   sync.Mutex
	dbOpen = map[string]*sealdb.DB{} // by home
)

// DB opens the sealed store of this home, once per process. With create,
// a home without store.db gets one, with a new key; without, it returns
// ErrNoStore, so a read makes no file and no key.
func DB(create bool) (*sealdb.DB, error) {
	dbMu.Lock()
	defer dbMu.Unlock()
	home := Home()
	if d := dbOpen[home]; d != nil {
		return d, nil
	}
	if KeySource == nil {
		return nil, errors.New("store: no key source (the vault package is not linked)")
	}
	ctx := context.Background()
	path := Path(StoreFile)
	meta, err := sealdb.Peek(ctx, path)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil, ErrNoStore
		}
		return createDB(ctx, home, path)
	}
	if err != nil {
		return nil, err
	}
	return openDB(ctx, home, path, meta)
}

func openDB(ctx context.Context, home, path string, meta map[string]string) (*sealdb.DB, error) {
	master, _, err := KeySource(meta, false)
	if err != nil {
		return nil, err
	}
	k, err := sealrow.NewKey(master)
	clear(master)
	if err != nil {
		return nil, err
	}
	d, err := sealdb.Open(ctx, path, k)
	if err != nil {
		return nil, err
	}
	dbOpen[home] = d
	return d, nil
}

func createDB(ctx context.Context, home, path string) (*sealdb.DB, error) {
	if err := ensureHome(); err != nil {
		return nil, err
	}
	unlock, err := Lock(storeLock)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// another process may have made it while this one waited
	if meta, err := sealdb.Peek(ctx, path); err == nil {
		return openDB(ctx, home, path, meta)
	}
	master, meta, err := KeySource(nil, true)
	if err != nil {
		return nil, err
	}
	k, err := sealrow.NewKey(master)
	clear(master)
	if err != nil {
		return nil, err
	}
	// made under a temporary name and moved into place with its settings,
	// so no process ever opens a store without its key mode
	tmp := path + ".new"
	_ = os.Remove(tmp)
	d, err := sealdb.Open(ctx, tmp, k)
	if err == nil {
		err = d.Update(ctx, func(tx *sealdb.Tx) error {
			for key, v := range meta {
				if err := tx.SetMeta(key, v); err != nil {
					return err
				}
			}
			return nil
		})
		if cerr := d.Close(); err == nil {
			err = cerr
		}
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return nil, err
	}
	d, err = sealdb.Open(ctx, path, k)
	if err != nil {
		return nil, err
	}
	dbOpen[home] = d
	return d, nil
}

// closeDBs closes every open store (tests that change the home).
func closeDBs() {
	dbMu.Lock()
	defer dbMu.Unlock()
	for h, d := range dbOpen {
		d.Close()
		delete(dbOpen, h)
	}
}
