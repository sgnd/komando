package store

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
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
// yet and KeySource picks the mode and returns the settings to keep. A
// create with meta key_mode "keyfile" keeps the new key out of the
// keychain (it could not be read): in a key file, or from the passphrase
// when one is given. The vault package sets it (it owns the keychain, key
// file and passphrase).
var KeySource func(meta map[string]string, create bool) (master []byte, newMeta map[string]string, err error)

// AgentCaller reports that an AI agent makes this call (the vault sets it
// from vault.AgentCall). Nil counts as an agent: a store is never started
// beside a keychain that cannot be read unless the caller is known to be
// a person or a script.
var AgentCaller func() bool

func agentCaller() bool { return AgentCaller == nil || AgentCaller() }

// Notice tells the person a one-line note on stderr (the cli sets it to
// the running calls' stderr). Nil: os.Stderr.
var Notice func(msg string)

func notice(msg string) {
	if Notice != nil {
		Notice(msg)
		return
	}
	fmt.Fprintln(os.Stderr, "komando: "+msg)
}

// ErrNoStore: a read of a fresh home, which has no store yet. Callers
// treat it as empty.
var ErrNoStore = errors.New("store: no store yet")

type openStore struct {
	db     *sealdb.DB
	fi     os.FileInfo // the file it opened, to notice a file put in its place
	master []byte      // its master key, made once per process (scrypt is slow)
	// until: a store opened unchecked, as the keychain did not answer in
	// time; it is opened and checked again from then on. Zero: checked.
	until time.Time
	// format2: a store of format 2, handed out to the migration only
	format2 bool
}

// The open stores, by home. dbOpen holds the stores every caller may use:
// checked ones, and ones opened unchecked for reading (a keychain that was
// slow or could not be read). lookOpen holds old copies opened to be
// looked at; only a caller that may look gets one, and nobody else ever
// closes one, so a call that may not look never pulls an open store from
// under a call that may.
//
// A handle that is no longer handed out (its file was replaced, its key
// changed, its check ran out, a person accepted the old copy) may still be
// in use by another call. It takes no more writes (StopWrites), so nothing
// goes through it into a file put aside, and it waits in retired. A sweep
// closes it once it was retired at least retireGrace ago and no step runs
// on it; a call that still holds it then gets STORE_CONFLICT, never a raw
// database error. Close closes the rest.
var (
	dbMu     sync.Mutex
	dbOpen   = map[string]openStore{}
	lookOpen = map[string]openStore{}
	retired  []retiredDB
)

type retiredDB struct {
	db *sealdb.DB
	at time.Time
}

// retireGrace is how long a retired handle stays open: a call uses a
// handle at once after it gets it. Tests shorten it.
var retireGrace = 10 * time.Second

// recheckAfter is how long a store opened unchecked, beside a keychain
// that could not be read, is handed out before it is opened and checked
// again (a slow keychain is left alone for slowFor). It bounds how many
// handles wait in retired.
const recheckAfter = 10 * time.Second

// storeChangedErr is the error of a step on a retired handle.
func storeChangedErr() error {
	return out.Errf(out.ExitConflict, "STORE_CONFLICT",
		"run the command again: komando opens the store again from the start; if it keeps happening, run `komando doctor`",
		"nothing was done: %s was replaced, given a new key or checked again while this command ran, and this command still held it as it was", Path(StoreFile))
}

// DB opens the sealed store of this home, once per process. With create,
// a home without store.db gets one, with a new key; without, it returns
// ErrNoStore, so a read makes no file and no key. An old copy stops with
// STORE_OLD_COPY unless OldCopyOK; then it opens to be read only.
func DB(create bool) (*sealdb.DB, error) {
	o, err := open(create, oldCopyOK())
	return o.db, err
}

// openOldCopy is DB for doctor's look at the store and for accepting an
// old copy: an old copy is opened to be looked at, never changed.
func openOldCopy() (*sealdb.DB, error) {
	o, err := open(false, true)
	return o.db, err
}

// open is DB; oldOK: the caller may look at an old copy.
func open(create, oldOK bool) (openStore, error) {
	o, err := cachedDB(create, oldOK, false)
	if errors.Is(err, errFormat2) {
		// the first open of a format-2 store: the migration, for a person
		// only, then the store as it is now
		if err := migrateOnOpen(); err != nil {
			return openStore{}, err
		}
		o, err = cachedDB(create, oldOK, false)
	}
	if err != nil {
		return openStore{}, err
	}
	// a store whose key another process changed since it was opened
	// (secret passphrase, secret keychain) is opened again once: writes
	// through the old handle would be sealed with the old key. Checked
	// outside dbMu, as the check waits for this handle's running step.
	if !errors.Is(o.db.View(context.Background(), func(*sealdb.Tx) error { return nil }), sealdb.ErrKeyChanged) {
		return o, nil
	}
	dbMu.Lock()
	home := Home()
	for _, m := range []map[string]openStore{dbOpen, lookOpen} {
		if c, ok := m[home]; ok && c.db == o.db {
			drop(m, home)
		}
	}
	dbMu.Unlock()
	return cachedDB(create, oldOK, false)
}

// errFormat2: the store is of format 2 and the caller is not the
// migration (open runs it first).
var errFormat2 = errors.New("store: the store is of format 2")

// openFormat2 opens a format-2 store for the migration: the normal open,
// with its old-copy count and policy MAC.
func openFormat2() (*sealdb.DB, error) {
	o, err := cachedDB(false, false, true)
	return o.db, err
}

// dropHome stops handing out this home's open stores (after the
// migration, whose handle reads format 2).
func dropHome() {
	dbMu.Lock()
	defer dbMu.Unlock()
	home := Home()
	for _, m := range []map[string]openStore{dbOpen, lookOpen} {
		if _, ok := m[home]; ok {
			drop(m, home)
		}
	}
}

// drop stops handing out m's store of home. The handle may still be in
// use by another call: it takes no more writes and is retired. Under dbMu.
func drop(m map[string]openStore, home string) {
	o := m[home]
	delete(m, home)
	if o.db.WritesStopped() == nil {
		o.db.StopWrites(storeChangedErr())
	}
	retired = append(retired, retiredDB{db: o.db, at: time.Now()})
}

// sweepRetired closes the retired handles that were retired at least
// retireGrace ago and run no step. Under dbMu.
func sweepRetired() {
	keep := retired[:0]
	for _, r := range retired {
		if time.Since(r.at) < retireGrace || !r.db.CloseIdle(storeChangedErr()) {
			keep = append(keep, r)
		}
	}
	clear(retired[len(keep):])
	retired = keep
}

// forgetOldCopy stops handing out this home's old copy, so the next look
// checks the store again (after doctor --accept-old-copy, the store opens
// as the newest copy, and can be written).
func forgetOldCopy() {
	dbMu.Lock()
	defer dbMu.Unlock()
	if _, ok := lookOpen[Home()]; ok {
		drop(lookOpen, Home())
	}
}

// cachedDB keeps the open stores of each home (dbOpen, lookOpen). An old
// copy is handed out only to a caller that may look at one (oldOK); any
// other caller gets the store opened and checked again, and
// STORE_OLD_COPY.
func cachedDB(create, oldOK, format2 bool) (openStore, error) {
	dbMu.Lock()
	defer dbMu.Unlock()
	sweepRetired()
	home := Home()
	path := DBPath()
	// a store removed or replaced (a restore from backup) since it was
	// opened is opened again, never written through the old handle
	fi, statErr := os.Stat(path)
	usable := func(o openStore) bool {
		return statErr == nil && os.SameFile(fi, o.fi) && (o.until.IsZero() || time.Now().Before(o.until)) && o.format2 == format2
	}
	if o, ok := dbOpen[home]; ok {
		if usable(o) {
			return o, nil
		}
		drop(dbOpen, home)
	}
	if o, ok := lookOpen[home]; ok && oldOK {
		if usable(o) {
			return o, nil
		}
		drop(lookOpen, home)
	}
	if KeySource == nil {
		return openStore{}, errors.New("store: no key source (the vault package is not linked)")
	}
	ctx := context.Background()
	meta, err := sealdb.Peek(ctx, path)
	if err == nil && (meta["format"] == "2") != format2 {
		if format2 {
			return openStore{}, fmt.Errorf("store: %s is of format %q, not 2", path, meta["format"])
		}
		return openStore{}, errFormat2
	}
	if err == nil {
		o, err := openDB(ctx, home, path, meta, oldOK, false)
		if !errors.Is(err, errStoreGone) {
			return o, err
		}
		// store.db went away after Peek: the checks of a missing store
	} else if !errors.Is(err, os.ErrNotExist) {
		return openStore{}, err
	}
	if create {
		return createDB(ctx, home, path)
	}
	if _, err := missingGuardedStore(false, oldOK); err != nil {
		return openStore{}, err // the keychain's count: doctor --accept-old-copy can clear it
	}
	if err := missingStore(); err != nil {
		return openStore{}, err
	}
	return openStore{}, ErrNoStore
}

// errStoreGone: store.db was removed between Peek and Open.
var errStoreGone = errors.New("store: store.db went away while it was opened")

// openDB opens the existing store at path; errStoreGone when it is no
// longer there (sealdb.Open never makes one). locked: the caller holds
// the store lock, which a store of format 1 is opened under, to be
// upgraded once (checkAndRemember).
func openDB(ctx context.Context, home, path string, meta map[string]string, oldOK, locked bool) (openStore, error) {
	if meta["format"] == "1" && !locked {
		unlock, err := Lock(storeLock)
		if err != nil {
			return openStore{}, err
		}
		defer unlock()
		// another process may have upgraded it while this one waited
		if meta, err = sealdb.Peek(ctx, path); errors.Is(err, os.ErrNotExist) {
			return openStore{}, errStoreGone
		} else if err != nil {
			return openStore{}, err
		}
	}
	master, _, err := KeySource(meta, false)
	if err != nil {
		return openStore{}, err
	}
	ks, err := keysFor(master, meta["format"])
	if err != nil {
		return openStore{}, err
	}
	d, err := sealdb.Open(ctx, path, ks.row)
	if errors.Is(err, os.ErrNotExist) {
		return openStore{}, errStoreGone
	}
	if err != nil {
		return openStore{}, err
	}
	if ks.policy != nil {
		if err := d.SetPolicy(ctx, ks.policy); err != nil {
			d.Close()
			return openStore{}, err
		}
	}
	// a store made before komando wrote store.made gets it now; a folder
	// komando cannot write to goes on without it
	_, _ = markStoreMade()
	return checkAndRemember(home, path, d, meta, master, oldOK, false)
}

// checkAndRemember compares d with the keychain's change count
// (checkGeneration) and keeps it as this home's open store, with the file
// it opened and its master key: a checked store, or one opened unchecked
// (a keychain that was slow or could not be read), for every caller; an
// old copy for callers that may look at one. made: this process just made
// d beside a keychain that could not be read, so it is the newest copy
// and has nothing to compare with.
func checkAndRemember(home, path string, d *sealdb.DB, meta map[string]string, master []byte, oldOK, made bool) (openStore, error) {
	var (
		state = checked
		raise func(uint64)
		err   error
	)
	if !made {
		state, raise, err = checkGeneration(d, meta, oldOK)
	}
	d.OnWait = waitNotice(os.Stderr)
	if err == nil && state == checked {
		d.OnGeneration = committer(raise)
		// the newest copy of a store an older komando made: given its
		// policy MAC now, under the store lock openDB took
		if meta["format"] == "1" {
			err = upgrade(d, master)
		}
	}
	var fi os.FileInfo
	if err == nil {
		fi, err = os.Stat(path)
	}
	if err != nil {
		d.Close()
		return openStore{}, err
	}
	o := openStore{db: d, fi: fi, master: master, format2: meta["format"] == "2"}
	switch state {
	case oldCopy:
		lookOpen[home] = o
	case unchecked:
		o.until = keychainSlowUntil()
		if o.until.IsZero() { // the keychain could not be read
			o.until = time.Now().Add(recheckAfter)
		}
		dbOpen[home] = o
	default:
		dbOpen[home] = o
	}
	return o, nil
}

// createDB makes this home's store. It never makes one in place of a
// store that went missing (missingGuardedStore, missingStore), whoever
// asks: a look at an old copy may read a missing store as none, never
// start an empty one, which would drop every pinned host key, rule and
// secret and lower the keychain's count.
func createDB(ctx context.Context, home, path string) (openStore, error) {
	if err := ensureHome(); err != nil {
		return openStore{}, err
	}
	unlock, err := Lock(storeLock)
	if err != nil {
		return openStore{}, err
	}
	defer unlock()
	// another process may have made it while this one waited; a caller
	// that makes a store has something to write, so never an old copy
	if meta, err := sealdb.Peek(ctx, path); err == nil {
		o, err := openDB(ctx, home, path, meta, false, true)
		if !errors.Is(err, errStoreGone) {
			return o, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return openStore{}, err // a store.db that cannot be read is never replaced
	}
	unread, err := missingGuardedStore(true, false)
	if err != nil {
		return openStore{}, err
	}
	if err := missingStore(); err != nil {
		return openStore{}, err
	}
	var want map[string]string
	if unread != nil {
		want = map[string]string{"key_mode": "keyfile"} // not in a keychain that cannot be read
	}
	master, meta, err := KeySource(want, true)
	if err != nil {
		return openStore{}, err
	}
	if unread != nil && meta["key_mode"] == "keychain" {
		return openStore{}, errors.New("store: the key of a new store went into a keychain that could not be read")
	}
	ks, err := keysFor(master, strconv.Itoa(sealdb.CreateFormat))
	if err != nil {
		return openStore{}, err
	}
	marked, err := writeNewStore(ctx, path, ks, meta)
	if err != nil {
		return openStore{}, err
	}
	d, err := sealdb.Open(ctx, path, ks.row)
	if err == nil && ks.policy != nil {
		if err = d.SetPolicy(ctx, ks.policy); err != nil {
			d.Close()
		}
	}
	if err != nil {
		return openStore{}, err
	}
	if unread != nil {
		o, err := checkAndRemember(home, path, d, meta, master, false, true)
		if err == nil {
			notice(newStoreNote(unread, meta))
		}
		return o, err
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
			if marked {
				os.Remove(Path(storeMade))
			}
			return openStore{}, fmt.Errorf("could not save the store's change count in the keychain: %w", gerr)
		}
	}
	return checkAndRemember(home, path, d, meta, master, false, false)
}

// writeNewStore makes the store at path with keys ks (its policy MAC
// too) and its readable settings meta: under a temporary name, moved into
// place with its settings, so no process ever opens a store without its
// key mode. The folder's lasting trace (storeMade) goes first: a crash
// after the move must not leave a store that, once store.db is lost,
// looks like none (missingStore found no trace, so this call writes it).
// marked: it wrote storeMade; on an error nothing is left.
func writeNewStore(ctx context.Context, path string, ks storeKeys, meta map[string]string) (marked bool, err error) {
	tmp := path + ".new"
	_ = os.Remove(tmp)
	d, err := sealdb.Create(ctx, tmp, ks.row)
	if err == nil {
		err = d.Update(ctx, func(tx *sealdb.Tx) error {
			for key, v := range meta {
				if err := tx.SetMeta(key, v); err != nil {
					return err
				}
			}
			if ks.policy == nil {
				return nil
			}
			return tx.SealPolicy(ks.policy)
		})
		if cerr := d.Close(); err == nil {
			err = cerr
		}
	}
	if err == nil {
		marked, err = markStoreMade()
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		if marked {
			os.Remove(Path(storeMade))
		}
		return false, err
	}
	return marked, nil
}

// newStoreNote is the note for a store made beside a keychain that could
// not be read (unread is the keychain's error).
func newStoreNote(unread error, meta map[string]string) string {
	guard := "its key file (store.key)"
	if meta["key_mode"] == "passphrase" {
		guard = "your passphrase"
	}
	return fmt.Sprintf("the keychain could not be read (%v), so the new store is guarded by %s only. Later commands only read while the keychain cannot be read; on a computer with no working keychain, set KOMANDO_KEYCHAIN=off.", unread, guard)
}

// Close closes every store this process has open; the next DB opens it
// again. A command calls it when it ends, an app when it quits, and a
// test before its folder is removed: Windows cannot remove a file that is
// still open.
func Close() {
	dbMu.Lock()
	defer dbMu.Unlock()
	for _, m := range []map[string]openStore{dbOpen, lookOpen} {
		for h, o := range m {
			o.db.Close()
			delete(m, h)
		}
	}
	for _, r := range retired {
		r.db.Close()
	}
	retired = nil
}

// MasterKey returns this home's sealed store master key, for keys made from
// it under other labels (the vault's entries). ErrNoStore when there is no
// store yet.
func MasterKey() ([]byte, error) {
	o, err := open(false, oldCopyOK())
	if err != nil {
		return nil, err
	}
	return bytes.Clone(o.master), nil
}

// Never call Rekey from inside Update or UpdateRuntime: it takes the
// runtime lock, which they hold.
//
// Rekey seals this home's store again under a new master key and keeps
// meta as its readable key settings, in one write step; then runs inside
// it, with the new key in force (the vault reseals its values there), and
// the safety rows get their policy MAC under the new policy key.
func Rekey(newMaster []byte, meta map[string]string, then func(tx *sealdb.Tx) error) error {
	d, err := DB(false)
	if err != nil {
		return err
	}
	// a store DB could not upgrade (it was not checked) is read only
	if m, err := sealdb.Peek(context.Background(), DBPath()); err != nil || m["format"] != newestFormat {
		return cmp.Or(err, fmt.Errorf("%s is of format %q; nothing was changed", Path(StoreFile), m["format"]))
	}
	ks, err := keysFor(newMaster, newestFormat)
	if err != nil {
		return err
	}
	newRT, err := runtimeKeyFrom(newMaster)
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
	err = d.Rekey(context.Background(), ks.row, func(tx *sealdb.Tx) error {
		for key, v := range meta {
			if err := tx.SetMeta(key, v); err != nil {
				return err
			}
		}
		if then != nil {
			if err := then(tx); err != nil {
				return err
			}
		}
		return tx.SealPolicy(ks.policy)
	})
	if err != nil {
		return err
	}
	rtKeyMu.Lock()
	rtKey, rtKeyHome = newRT, Home()
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
	sealed, err := newRT.Seal(runtimeRow, rtPlain)
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
// moved out of the keychain into a key file, a move under way).
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

// waitNotice is the store's OnWait: one line on w while a write waits.
func waitNotice(w io.Writer) func() {
	return func() {
		fmt.Fprintln(w, "komando: waiting for another komando process to finish with komando's store (up to a minute to start a change and a minute to save it)")
	}
}
