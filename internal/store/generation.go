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
// A store with its key in a key file or a passphrase has no keychain to
// compare with, and no such protection; doctor says so.

// GenerationKeep reads and writes the number in the keychain.
type GenerationKeep struct {
	Get func() (n uint64, ok bool, err error)
	Set func(n uint64) error
	Del func() // the store went aside (a failed move, an undo)
}

// GenerationKeeper is set by the vault package (it owns the keychain).
var GenerationKeeper GenerationKeep

// AllowOldCopy lets this process open an old copy (doctor and dry runs:
// they change nothing, and doctor must be able to say what is wrong).
var AllowOldCopy bool

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
	ch := make(chan answer, 1)
	go func() { k, ok, err := keptCount(); ch <- answer{k, ok, err} }()
	select {
	case a := <-ch:
		return a.k, a.ok, a.err
	case <-time.After(probeAnswer):
		slowMu.Lock()
		slowUntil = time.Now().Add(time.Minute)
		slowMu.Unlock()
		return 0, false, ErrKeychainSlow
	}
}

// ErrKeychainSlow wraps a keychain that did not answer in time. Only this
// lets a command go on unchecked, and then only to read (the keychain gave
// the key a moment ago; a busy one must not stop all work, but nothing is
// changed on a store that was not checked); doctor warns about it.
var ErrKeychainSlow = errors.New("store: the keychain did not answer in time")

func oldCopyErr(have, kept uint64, why string) error {
	return out.Errf(out.ExitPolicy, "STORE_OLD_COPY",
		"if the komando folder was restored from a backup on purpose, a person runs `komando doctor --accept-old-copy` in their own terminal; otherwise find out who put an old copy back or changed the keychain",
		"%s %s: servers, rules, secrets or pinned host keys may be old", Path(StoreFile), why)
}

// checkGeneration compares d's generation with the keychain's when the
// home is guarded (see guarded). It returns whether d is an old copy
// opened only to be looked at (AllowOldCopy), and the hook to raise the
// keychain's count after each changing commit (nil when not guarded).
func checkGeneration(d *sealdb.DB, meta map[string]string) (lookOnly bool, raise func(uint64), err error) {
	if GenerationKeeper.Get == nil {
		return false, nil, nil
	}
	get := keptCount
	if !keychainMode(meta) {
		get = probeCount
	}
	kept, ok, kerr := get()
	if !keychainMode(meta) && (kerr != nil || !ok) {
		return false, nil, nil // key file or passphrase, and no count: nothing to compare with
	}
	have, err := d.Generation(context.Background())
	if err != nil {
		return false, nil, err
	}
	switch {
	case errors.Is(kerr, ErrKeychainSlow):
		// look only, and opened again (and checked) on the next use
		d.NoWrites = out.Errf(out.ExitError, "KEYCHAIN_SLOW",
			"run it again in a moment; if it keeps happening, run `komando doctor`",
			"nothing was changed: the keychain did not answer in time, so komando could not check that %s is the newest copy", Path(StoreFile))
		return true, nil, nil
	case kerr != nil || !ok:
		// a store whose key is in the keychain always has its number there:
		// a missing or unreadable one was removed or changed
		why := "has no change count in the keychain"
		if kerr != nil {
			why = "has a change count in the keychain that cannot be read (" + kerr.Error() + ")"
		}
		if AllowOldCopy {
			return true, nil, nil
		}
		return false, nil, oldCopyErr(have, 0, why)
	case have < kept:
		if AllowOldCopy {
			return true, nil, nil
		}
		return false, nil, oldCopyErr(have, kept, fmt.Sprintf("is an older copy (change %d) than this computer's keychain remembers (change %d)", have, kept))
	case have > kept:
		_ = GenerationKeeper.Set(have)
		kept = have
	}
	return false, raiser(kept), nil
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
// every pinned host key, rule and secret.
func missingGuardedStore() error {
	if GenerationKeeper.Get == nil || AllowOldCopy {
		return nil
	}
	kept, ok, err := probeCount()
	if err != nil || !ok {
		return nil
	}
	return out.Errf(out.ExitPolicy, "STORE_OLD_COPY",
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
	saved := AllowOldCopy
	AllowOldCopy = true
	defer func() { AllowOldCopy = saved; closeDBs() }()
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
	d, err := DB(false)
	if err != nil {
		return 0, err
	}
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
	if err != nil || !guarded(meta) {
		return 0, 0, false, false, nil
	}
	saved := AllowOldCopy
	AllowOldCopy = true
	defer func() { AllowOldCopy = saved; closeDBs() }()
	d, err := DB(false)
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

// slowUntil is when a keychain that did not answer in time is asked again:
// a hung keychain tool costs one wait, not one per check in a command.
var (
	slowMu    sync.Mutex
	slowUntil time.Time
)

// keptCount asks GenerationKeeper.Get, unless the keychain was slow less
// than a minute ago.
func keptCount() (uint64, bool, error) {
	slowMu.Lock()
	skip := time.Now().Before(slowUntil)
	slowMu.Unlock()
	if skip {
		return 0, false, ErrKeychainSlow
	}
	k, ok, err := GenerationKeeper.Get()
	if errors.Is(err, ErrKeychainSlow) {
		slowMu.Lock()
		slowUntil = time.Now().Add(time.Minute)
		slowMu.Unlock()
	}
	return k, ok, err
}
