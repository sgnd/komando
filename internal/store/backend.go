package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealrow"
)

// The sealed store: one SQLite file, store.db,
// whose records are sealed. It is the only place komando keeps its data; a
// home without store.db (and no sign it had one) starts fresh.

// StoreFile is the sealed store's file name in the home folder.
const StoreFile = "store.db"

// storeLock keeps two komando processes from making a fresh store at once
// (each with its own key).
const storeLock = ".store.lock"

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
	// lookOnly: an old copy opened for a caller that may look at one
	// (doctor, a dry run); never handed to a caller that may not
	lookOnly bool
}

var (
	dbMu   sync.Mutex
	dbOpen = map[string]openStore{} // by home
)

// DB opens the sealed store of this home, once per process. With create,
// a home without store.db gets one, with a new key; without, it returns
// ErrNoStore, so a read makes no file and no key. An old copy stops with
// STORE_OLD_COPY unless OldCopyOK.
func DB(create bool) (*sealdb.DB, error) { return db(create, oldCopyOK()) }

// openOldCopy is DB for doctor's look at the store and for accepting an
// old copy: an old copy is opened to be looked at.
func openOldCopy() (*sealdb.DB, error) { return db(false, true) }

// db is DB; oldOK: the caller may look at an old copy.
func db(create, oldOK bool) (*sealdb.DB, error) {
	d, err := cachedDB(create, oldOK)
	if err != nil {
		return nil, err
	}
	// a store whose key another process changed since it was opened
	// (secret passphrase, secret keychain) is opened again once: writes
	// through the old handle would be sealed with the old key. Checked
	// outside dbMu, as the check waits for this handle's running step.
	if !errors.Is(d.View(context.Background(), func(*sealdb.Tx) error { return nil }), sealdb.ErrKeyChanged) {
		return d, nil
	}
	dbMu.Lock()
	if o, ok := dbOpen[Home()]; ok && o.db == d {
		d.Close()
		delete(dbOpen, Home())
	}
	dbMu.Unlock()
	return cachedDB(create, oldOK)
}

// dropLookOnly closes this home's open store when it is an old copy opened
// only to be looked at, so the next open checks the store again (after
// doctor --accept-old-copy, a normal handle that raises the keychain).
func dropLookOnly() {
	dbMu.Lock()
	defer dbMu.Unlock()
	if o, ok := dbOpen[Home()]; ok && o.lookOnly {
		o.db.Close()
		delete(dbOpen, Home())
	}
}

// cachedDB keeps one open store per home. A look-only handle (an old copy)
// is handed out only to a caller that may look at one (oldOK); any other
// caller gets the store opened and checked again.
func cachedDB(create, oldOK bool) (*sealdb.DB, error) {
	dbMu.Lock()
	defer dbMu.Unlock()
	home := Home()
	if o, ok := dbOpen[home]; ok {
		// a store removed or replaced (a restore from backup) since it was
		// opened is opened again, never written through the old handle
		if fi, err := os.Stat(DBPath()); err == nil && os.SameFile(fi, o.fi) && (!o.lookOnly || oldOK) {
			return o.db, nil
		}
		o.db.Close()
		delete(dbOpen, home)
	}
	if KeySource == nil {
		return nil, errors.New("store: no key source (the vault package is not linked)")
	}
	ctx := context.Background()
	path := DBPath()
	meta, err := sealdb.Peek(ctx, path)
	if errors.Is(err, os.ErrNotExist) {
		if err := missingGuardedStore(oldOK); err != nil {
			return nil, err // the keychain's count: doctor --accept-old-copy can clear it
		}
		if err := missingStore(); err != nil {
			return nil, err
		}
		if !create {
			return nil, ErrNoStore
		}
		return createDB(ctx, home, path, oldOK)
	}
	if err != nil {
		return nil, err
	}
	return openDB(ctx, home, path, meta, oldOK)
}

func openDB(ctx context.Context, home, path string, meta map[string]string, oldOK bool) (*sealdb.DB, error) {
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
	lookOnly, raise, err := checkGeneration(d, meta, oldOK)
	if err != nil {
		d.Close()
		return nil, err
	}
	if !lookOnly {
		d.OnGeneration = committer(raise)
	}
	return remember(home, path, d, master, lookOnly)
}

// remember keeps d as this home's open store, with the file it opened
// and its master key.
func remember(home, path string, d *sealdb.DB, master []byte, lookOnly bool) (*sealdb.DB, error) {
	fi, err := os.Stat(path)
	if err != nil {
		d.Close()
		return nil, err
	}
	dbOpen[home] = openStore{d, fi, master, lookOnly}
	return d, nil
}

func createDB(ctx context.Context, home, path string, oldOK bool) (*sealdb.DB, error) {
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
		return openDB(ctx, home, path, meta, oldOK)
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
	// a new store's number goes into the keychain with it: from now on a
	// missing number is never normal
	if guarded(meta) {
		n, gerr := d.Generation(ctx)
		if gerr == nil && GenerationKeeper.Set != nil {
			gerr = GenerationKeeper.Set(n)
		}
		if gerr != nil {
			// without its number the new store would be taken for an old
			// copy on the next run: start again next time instead
			d.Close()
			os.Remove(path)
			return nil, fmt.Errorf("could not save the store's change count in the keychain: %w", gerr)
		}
	}
	lookOnly, raise, err := checkGeneration(d, meta, oldOK)
	if err != nil {
		d.Close()
		return nil, err
	}
	if !lookOnly {
		d.OnGeneration = committer(raise)
	}
	return remember(home, path, d, master, lookOnly)
}

// Close closes every store this process has open; the next DB opens it
// again. A command calls it when it ends, and a test before its folder is
// removed: Windows cannot remove a file that is still open.
func Close() {
	dbMu.Lock()
	defer dbMu.Unlock()
	for h, o := range dbOpen {
		o.db.Close()
		delete(dbOpen, h)
	}
}

// closeDBs closes every open store (tests that change the home).
func closeDBs() { Close() }

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

// CheckWritable opens this home's store (making it on a fresh home) and
// checks the file can be written, so a command that changes something,
// and records it in the audit log, finds out before it runs.
func CheckWritable() error {
	if _, err := DB(true); err != nil {
		return storeErr(err)
	}
	f, err := os.OpenFile(DBPath(), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	return f.Close()
}
