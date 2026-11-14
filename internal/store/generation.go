package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// Old-copy protection: the
// sealed store counts its changes (sealdb's generation), and a store whose
// key is in the OS keychain keeps the same number there. The store is
// written first, then the keychain:
//   - store higher than the keychain: normal after a crash or a keychain
//     that was locked at the time; the keychain is raised.
//   - store lower than the keychain: an old copy was put back; commands
//     stop with STORE_OLD_COPY until a person accepts it on purpose.
// A store with its key in a key file or a passphrase is compared only when
// the keychain keeps a count for this home (a backup from before `secret
// keychain`). When the keychain cannot say whether it keeps one (locked,
// slow, broken), such a store is read but never changed: it may be that
// backup. Where the keychain answers "no count", or there is none, there
// is no such protection; doctor says so.

// GenerationKeep reads and writes the number in the keychain.
type GenerationKeep struct {
	Get func() (n uint64, ok bool, err error)
	Set func(n uint64) error
	Del func() // the store went aside (a failed move, an undo)
}

// GenerationKeeper is set by the vault package (it owns the keychain).
var GenerationKeeper GenerationKeep

// NoKeychain is the error of a GenerationKeep.Get that found no keychain
// on this computer to ask (turned off, or no keychain tool): no count can
// be kept there, so there is none. Any other error means a count may be
// there but could not be read.
type NoKeychain struct{ Err error }

func (e NoKeychain) Error() string { return e.Err.Error() }
func (e NoKeychain) Unwrap() error { return e.Err }

// noCount reports a Get that says no count is kept: none in the keychain,
// or no keychain at all.
func noCount(ok bool, err error) bool {
	var nk NoKeychain
	return (err == nil && !ok) || errors.As(err, &nk)
}

// OldCopyOK says whether an old copy may be opened to be looked at. The
// commands that may look are doctor and dry runs: they change nothing, and
// doctor must be able to say what is wrong. The cli sets it: true only
// while every command running in the process may look, so one command's
// allowance never opens an old copy for another. Nil means never.
var OldCopyOK func() bool

// oldCopyOK asks OldCopyOK.
func oldCopyOK() bool { return OldCopyOK != nil && OldCopyOK() }

// ErrOldCopy: the store is older than the keychain says.
var ErrOldCopy = errors.New("store: an older copy than the keychain's")

// keychainMode reports a store whose key is in the keychain: it always has
// a change count there.
func keychainMode(meta map[string]string) bool {
	return meta["key_mode"] == "keychain" && GenerationKeeper.Get != nil
}

// guarded reports whether this home's store is compared with a change
// count in the keychain: its key is there, or the keychain holds a count
// for this home whatever the store's readable key_mode says (key_mode is
// not sealed: a backup from before `secret keychain` says keyfile).
func guarded(meta map[string]string) bool {
	if keychainMode(meta) {
		return true
	}
	if GenerationKeeper.Get == nil {
		return false
	}
	_, ok, err := probeCount()
	return err == nil && ok
}

// probeAnswer bounds probeCount: a home whose key is not in the keychain
// asks it only in case a count was left there, so a hung keychain tool
// must not hold up every command.
var probeAnswer = time.Second

// probeCount is keptCount for a home whose key is elsewhere (a key file or
// a passphrase): an answer later than probeAnswer counts as slow.
func probeCount() (uint64, bool, error) {
	type answer struct {
		k   uint64
		ok  bool
		err error
	}
	home := Home()
	ch := make(chan answer, 1)
	go func() { k, ok, err := keptCountOf(home); ch <- answer{k, ok, err} }()
	select {
	case a := <-ch:
		return a.k, a.ok, a.err
	case <-time.After(probeAnswer):
		markKeychainSlow(home)
		return 0, false, ErrKeychainSlow
	}
}

// ErrKeychainSlow wraps a keychain that did not answer in time. A command
// goes on unchecked then, and only to read (a busy keychain must not stop
// all work, but nothing is changed on a store that was not checked);
// doctor warns about it. So does a keychain that could not be read beside
// a store whose key is elsewhere (checkGeneration).
var ErrKeychainSlow = errors.New("store: the keychain did not answer in time")

func oldCopyErr(have, kept uint64, why string) error {
	return out.Errf(out.ExitPolicy, "STORE_OLD_COPY",
		"if the komando folder was restored from a backup on purpose, a person runs `komando doctor --accept-old-copy` in their own terminal; otherwise find out who put an old copy back or changed the keychain",
		"%s %s: servers, rules, secrets or pinned host keys may be old", Path(StoreFile), why)
}

// copyCheck is what checkGeneration found.
type copyCheck int

const (
	checked   copyCheck = iota // the newest copy, or nothing to compare with
	unchecked                  // the keychain did not answer in time: read only
	oldCopy                    // an old copy, opened only to be looked at
)

// lookOnlyErr is the error of a write to an old copy opened to be looked
// at: nothing is ever saved into one (its change count would climb back
// to the keychain's, and the old copy would pass for the newest).
func lookOnlyErr() error {
	return out.Errf(out.ExitPolicy, "STORE_OLD_COPY",
		"if the komando folder was restored from a backup on purpose, a person runs `komando doctor --accept-old-copy` in their own terminal",
		"nothing was changed: %s is an older copy than this computer's keychain remembers, opened only to be looked at", Path(StoreFile))
}

// checkGeneration compares d's generation with the keychain's when the
// home is guarded (see guarded). It says whether d is checked, unchecked
// (the keychain was slow, or could not be read beside a store whose key
// is elsewhere: read only) or an old copy opened only to be looked at
// (oldOK: the caller may look at one; read only), and gives the hook to
// raise the keychain's count after each changing commit (nil when not
// guarded). A store it does not find checked takes no writes.
func checkGeneration(d *sealdb.DB, meta map[string]string, oldOK bool) (state copyCheck, raise func(uint64), err error) {
	if GenerationKeeper.Get == nil {
		return checked, nil, nil
	}
	get := keptCount
	if !keychainMode(meta) {
		get = probeCount
	}
	kept, ok, kerr := get()
	if !keychainMode(meta) && noCount(ok, kerr) {
		return checked, nil, nil // key file or passphrase, and no count kept: nothing to compare with
	}
	have, err := d.Generation(context.Background())
	if err != nil {
		return checked, nil, err
	}
	switch {
	case errors.Is(kerr, ErrKeychainSlow):
		// read only, and opened again (and checked) once the keychain
		// is asked again
		d.StopWrites(out.Errf(out.ExitError, "KEYCHAIN_SLOW",
			"run it again in a moment; if it keeps happening, run `komando doctor`",
			"nothing was changed: the keychain did not answer in time, so komando could not check that %s is the newest copy", Path(StoreFile)))
		return unchecked, nil, nil
	case kerr != nil && !keychainMode(meta):
		// a key file or a passphrase, and a keychain that could not say
		// whether it keeps a count for this home: this may be a backup
		// from before `secret keychain`, so it is read, never changed
		if oldOK {
			d.StopWrites(lookOnlyErr())
			return oldCopy, nil, nil
		}
		d.StopWrites(out.Errf(out.ExitRemote, "KEYCHAIN_FAILED",
			"a person unlocks the keychain (an AI agent asks the user), then run it again; on a computer with no working keychain, a person sets KOMANDO_KEYCHAIN=off",
			"nothing was changed: the keychain could not be read (%v), so komando could not check that %s is the newest copy", kerr, Path(StoreFile)))
		return unchecked, nil, nil
	case kerr != nil || !ok:
		// a store whose key is in the keychain always has its number there:
		// a missing or unreadable one was removed or changed
		why := "has no change count in the keychain"
		if kerr != nil {
			why = "has a change count in the keychain that cannot be read (" + kerr.Error() + ")"
		}
		if oldOK {
			d.StopWrites(lookOnlyErr())
			return oldCopy, nil, nil
		}
		return checked, nil, oldCopyErr(have, 0, why)
	case have < kept:
		if oldOK {
			d.StopWrites(lookOnlyErr())
			return oldCopy, nil, nil
		}
		return checked, nil, oldCopyErr(have, kept, fmt.Sprintf("is an older copy (change %d) than this computer's keychain remembers (change %d)", have, kept))
	case have > kept:
		_ = GenerationKeeper.Set(have)
		kept = have
	}
	return checked, raiser(kept), nil
}

// raiser is the hook after a commit that changed data: it only ever
// raises the keychain's count, from the last count this process knows,
// with no second look at the store or the keychain.
func raiser(last uint64) func(uint64) {
	var mu sync.Mutex
	return func(n uint64) {
		mu.Lock()
		defer mu.Unlock()
		if n <= last {
			return
		}
		if GenerationKeeper.Set(n) == nil {
			last = n
		}
	}
}

// missingGuardedStore stops a home whose store.db is gone while the keychain
// still holds its change count: making a fresh store would silently drop
// every pinned host key, rule and secret, and lower the count.
//
// create: the caller would make a store. It never does over a kept count.
// When the keychain cannot say whether one is kept (slow, locked, broken),
// it makes one only for a person or a script (not an AI agent), and only
// in a folder with no trace of a store (storeTrace): then unread is the
// keychain's error, and the new store keeps its key out of the keychain.
// A home whose keychain answers "no count", or a computer with no
// keychain at all, gets a new store. A read (no create) that may look at
// an old copy (oldOK) goes on: a missing store is the oldest copy, and a
// look changes nothing. So does a read beside a keychain that cannot
// answer, as reads go on beside a slow keychain. Such a read sees no
// store, or STATE_CORRUPT when the folder shows it had one (missingStore).
func missingGuardedStore(create, oldOK bool) (unread, err error) {
	if GenerationKeeper.Get == nil {
		return nil, nil
	}
	kept, ok, kerr := probeCount()
	switch {
	case noCount(ok, kerr):
		return nil, nil // a new home
	case kerr != nil && !create:
		return nil, nil
	case kerr != nil:
		trace := storeTrace()
		if trace == "" && !agentCaller() {
			return kerr, nil // a person's first store, beside a keychain that cannot be read
		}
		// first put store.db back; a fresh start only for a folder that never had a store
		hint := "put store.db back from a backup, then run it again once the keychain answers (`komando doctor` checks it)"
		had := " (this folder had a store: " + trace + ")"
		if trace == "" {
			hint = "if this folder had a store, put store.db back from a backup; if it never had one, a person runs the command in their own terminal (or with KOMANDO_KEYCHAIN=off), which starts a store with its key in a key file"
			had = ""
		}
		if errors.Is(kerr, ErrKeychainSlow) {
			return nil, out.Errf(out.ExitError, "KEYCHAIN_SLOW", hint,
				"nothing was changed: %s is missing%s, and the keychain did not answer in time, so komando could not check that this folder never had a store; it does not start an empty one", Path(StoreFile), had)
		}
		return nil, out.Errf(out.ExitPolicy, "STORE_OLD_COPY", hint,
			"%s is missing%s, and this computer's keychain could not say whether it remembers a change count for this folder (%v): komando does not start an empty store in its place (every pinned host key and rule would be gone)", Path(StoreFile), had, kerr)
	case !create && oldOK:
		return nil, nil
	}
	return nil, out.Errf(out.ExitPolicy, "STORE_OLD_COPY",
		"put store.db back from a backup; to start an empty store on purpose, a person runs `komando doctor --accept-old-copy` in their own terminal",
		"%s is missing, though this computer's keychain remembers its change %d: komando does not start an empty store in its place (every pinned host key and rule would be gone)", Path(StoreFile), kept)
}

// StartGeneration writes the keychain's number for a store whose key has
// just gone into the keychain (a new store, `secret keychain`), so a
// missing number is never normal.
func StartGeneration() error {
	if GenerationKeeper.Set == nil {
		return nil
	}
	d, err := DB(false)
	if err != nil {
		return err
	}
	n, err := d.Generation(context.Background())
	if err != nil {
		return err
	}
	return GenerationKeeper.Set(n)
}

// AcceptOldCopy makes the keychain remember this store's number, so an
// old copy put back on purpose (a restore) is used from now on. want is
// the number the person saw and said yes to: another one is refused. For
// a person only: the caller checks.
func AcceptOldCopy(want uint64) (from uint64, err error) {
	if _, err := os.Stat(DBPath()); errors.Is(err, os.ErrNotExist) {
		// store.db is gone: the person starts an empty store on purpose,
		// so the keychain forgets the old count
		if want != 0 {
			return 0, fmt.Errorf("the folder changed since the question; nothing was accepted, run it again")
		}
		from, _, _ = keptCount()
		if GenerationKeeper.Del != nil {
			GenerationKeeper.Del()
		}
		return from, nil
	}
	d, err := openOldCopy()
	if err != nil {
		return 0, err
	}
	// from now on the store opens as the newest copy, and can be written
	defer forgetOldCopy()
	meta, err := sealdb.Peek(context.Background(), DBPath())
	if err != nil {
		return 0, err
	}
	if !guarded(meta) {
		return 0, errors.New("this store's key is not in the keychain, so there is no number to accept")
	}
	have, err := d.Generation(context.Background())
	if err != nil {
		return 0, err
	}
	if have != want {
		return 0, fmt.Errorf("the folder changed since the question (change %d, not %d); nothing was accepted, run it again", have, want)
	}
	from, _, _ = keptCount()
	return from, GenerationKeeper.Set(have)
}

// CopyState says how this home's store compares with the keychain:
// guarded is false when its key is not in the keychain (no protection);
// slow when the keychain did not answer, so nothing was compared.
func CopyState() (have, kept uint64, guardedStore, old bool, err error) {
	meta, err := sealdb.Peek(context.Background(), DBPath())
	if errors.Is(err, os.ErrNotExist) && GenerationKeeper.Get != nil {
		// no store.db while the keychain still remembers one: as old as it gets
		if k, ok, kerr := probeCount(); kerr == nil && ok {
			return 0, k, true, true, nil
		}
	}
	if err != nil {
		return 0, 0, false, false, nil
	}
	if !keychainMode(meta) {
		if GenerationKeeper.Get == nil {
			return 0, 0, false, false, nil
		}
		_, ok, perr := probeCount()
		switch {
		case noCount(ok, perr):
			return 0, 0, false, false, nil
		case perr != nil:
			// its key is elsewhere, and the keychain cannot say whether it
			// keeps a newer count: the store is read, never changed
			return 0, 0, false, false, fmt.Errorf("the keychain could not be read (%v), so komando cannot check that %s is not a backup from before `komando secret keychain`; until it can, komando changes nothing in it", perr, StoreFile)
		}
	}
	d, err := openOldCopy()
	if err != nil {
		return 0, 0, true, false, err
	}
	if have, err = d.Generation(context.Background()); err != nil {
		return 0, 0, true, false, err
	}
	kept, ok, err := keptCount()
	if err != nil {
		return have, 0, true, !errors.Is(err, ErrKeychainSlow), err
	}
	if !ok {
		return have, 0, true, true, nil
	}
	return have, kept, true, have < kept, nil
}

// slowUntil is, by home, when a keychain that did not answer in time is
// asked again for that home's count: a hung keychain tool costs one wait,
// not one per check in a command. By home, as each home has its own count
// (and a test its own home).
var (
	slowMu    sync.Mutex
	slowUntil = map[string]time.Time{}
)

// slowFor is how long a keychain that did not answer is left alone.
const slowFor = time.Minute

// markKeychainSlow notes that the keychain did not answer for home. The
// home is the one asked: an answer that comes late (from a probe that
// gave up waiting) never marks the home in use by then.
func markKeychainSlow(home string) {
	slowMu.Lock()
	defer slowMu.Unlock()
	slowUntil[home] = time.Now().Add(slowFor)
}

// keychainSlowUntil is when the keychain is asked again for this home's
// count (zero: it was not slow).
func keychainSlowUntil() time.Time {
	slowMu.Lock()
	defer slowMu.Unlock()
	return slowUntil[Home()]
}

// keptCount asks GenerationKeeper.Get, unless the keychain was slow for
// this home less than a minute ago.
func keptCount() (uint64, bool, error) { return keptCountOf(Home()) }

// keptCountOf is keptCount for home, the home in use when it was asked.
func keptCountOf(home string) (uint64, bool, error) {
	slowMu.Lock()
	skip := time.Now().Before(slowUntil[home])
	slowMu.Unlock()
	if skip {
		return 0, false, ErrKeychainSlow
	}
	k, ok, err := GenerationKeeper.Get()
	if errors.Is(err, ErrKeychainSlow) {
		markKeychainSlow(home)
	}
	return k, ok, err
}
