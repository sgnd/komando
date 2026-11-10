package store

import (
	"bytes"
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

// freshSealed makes a fresh home use the sealed store. Test suites turn
// it off to test the file backend (UseSealedForNewHomes).
var freshSealed = true

// legacyFiles are files only the file backend writes, and that hold data.
// vault.key alone does not count (the sealed store's key file has its own
// name), nor does audit.jsonl: every command may write it before its first
// change, and a home with only an audit log holds no inventory.
var legacyFiles = []string{"state.json", "vault.json", "known_hosts"}

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

type openStore struct {
	db     *sealdb.DB
	fi     os.FileInfo // the file it opened, to notice a file put in its place
	master []byte      // its master key, made once per process (scrypt is slow)
}

var (
	dbMu   sync.Mutex
	dbOpen = map[string]openStore{} // by home
)

// DB opens the sealed store of this home, once per process. With create,
// a home without store.db gets one, with a new key; without, it returns
// ErrNoStore, so a read makes no file and no key.
func DB(create bool) (*sealdb.DB, error) {
	dbMu.Lock()
	defer dbMu.Unlock()
	home := Home()
	if o, ok := dbOpen[home]; ok {
		// a store removed or replaced (a restore from backup) since it was
		// opened is opened again, never written through the old handle
		if fi, err := os.Stat(Path(StoreFile)); err == nil && os.SameFile(fi, o.fi) {
			return o.db, nil
		}
		o.db.Close()
		delete(dbOpen, home)
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
	if err != nil {
		return nil, err
	}
	d, err := sealdb.Open(ctx, path, k)
	if err != nil {
		return nil, err
	}
	return remember(home, path, d, master)
}

// remember keeps d as this home's open store, with the file it opened
// and its master key.
func remember(home, path string, d *sealdb.DB, master []byte) (*sealdb.DB, error) {
	fi, err := os.Stat(path)
	if err != nil {
		d.Close()
		return nil, err
	}
	dbOpen[home] = openStore{d, fi, master}
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
	return remember(home, path, d, master)
}

// closeDBs closes every open store (tests that change the home).
func closeDBs() {
	dbMu.Lock()
	defer dbMu.Unlock()
	for h, o := range dbOpen {
		o.db.Close()
		delete(dbOpen, h)
	}
}

// MasterKey returns this home's sealed store master key, for keys made from
// it under other labels (the vault's entries). ErrNoStore when there is no
// store yet.
func MasterKey() ([]byte, error) {
	if _, err := DB(false); err != nil {
		return nil, err
	}
	dbMu.Lock()
	defer dbMu.Unlock()
	o, ok := dbOpen[Home()]
	if !ok {
		return nil, ErrNoStore
	}
	return bytes.Clone(o.master), nil
}

// Never call Rekey from inside Update or UpdateRuntime: it takes the
// runtime lock, which they hold.
//
// Rekey seals this home's store again under a new master key and keeps
// meta as its readable key settings, in one write step; then runs inside
// it, with the new key in force (the vault reseals its values there).
func Rekey(newMaster []byte, meta map[string]string, then func(tx *sealdb.Tx) error) error {
	d, err := DB(false)
	if err != nil {
		return err
	}
	k, err := sealrow.NewKey(newMaster)
	if err != nil {
		return err
	}
	// runtime.json is sealed with the same key: hold it still, read it
	// with the old key, and seal it again with the new one after
	unlockRT, err := Lock(runtimeLock)
	if err != nil {
		return err
	}
	defer unlockRT()
	var rtPlain []byte
	if b, err := os.ReadFile(runtimePath()); err == nil {
		if rtPlain, err = openRuntime(b); err != nil {
			return err
		}
	}
	err = d.Rekey(context.Background(), k, func(tx *sealdb.Tx) error {
		for key, v := range meta {
			if err := tx.SetMeta(key, v); err != nil {
				return err
			}
		}
		if then != nil {
			return then(tx)
		}
		return nil
	})
	if err != nil {
		return err
	}
	rtKeyMu.Lock()
	rtKey, rtKeyHome = k, Home()
	rtKeyMu.Unlock()
	dbMu.Lock()
	if o, ok := dbOpen[Home()]; ok {
		o.master = bytes.Clone(newMaster)
		dbOpen[Home()] = o
	}
	dbMu.Unlock()
	// the store has its new key now: nothing below may report a failure,
	// or the caller would undo a change that is already made. runtime.json
	// holds only running sessions, found or made again: when it cannot be
	// sealed again, it goes.
	if rtPlain == nil {
		return nil
	}
	sealed, err := k.Seal(runtimeRow, rtPlain)
	clear(rtPlain)
	if err == nil {
		err = WriteFileAtomic(runtimePath(), append(append([]byte{}, runtimeMagic...), sealed...), 0o600)
	}
	if err != nil {
		_ = os.Remove(runtimePath())
	}
	return nil
}

// SetStoreMeta changes readable key settings of this home's store (a key
// moved between the keychain and a key file: the same key, kept elsewhere).
func SetStoreMeta(meta map[string]string) error {
	d, err := DB(false)
	if err != nil {
		return err
	}
	return d.Update(context.Background(), func(tx *sealdb.Tx) error {
		for k, v := range meta {
			if err := tx.SetMeta(k, v); err != nil {
				return err
			}
		}
		return nil
	})
}
