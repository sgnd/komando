package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// Old-copy protection (docs/design/sync-security.md section 16): the
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

// guarded reports whether this home's store is guarded by the keychain.
func guarded(meta map[string]string) bool {
	return meta["key_mode"] == "keychain" && GenerationKeeper.Get != nil
}

// ErrKeychainSlow wraps a keychain that did not answer in time. Only this
// lets a command go on unchecked (the keychain gave the key a moment ago;
// a busy one must not stop all work); doctor warns about it.
var ErrKeychainSlow = errors.New("store: the keychain did not answer in time")

func oldCopyErr(have, kept uint64, why string) error {
	return out.Errf(out.ExitPolicy, "STORE_OLD_COPY",
		"if the komando folder was restored from a backup on purpose, a person runs `komando doctor --accept-old-copy` in their own terminal; otherwise find out who put an old copy back or changed the keychain",
		"%s %s: servers, rules, secrets or pinned host keys may be old", Path(StoreFile), why)
}

// checkGeneration compares d's generation with the keychain's when the
// store's key is in the keychain. It returns whether d is an old copy
// opened only to be looked at (AllowOldCopy): such a handle never writes
// the keychain.
func checkGeneration(d *sealdb.DB, meta map[string]string) (lookOnly bool, err error) {
	if !guarded(meta) {
		return false, nil
	}
	have, err := d.Generation(context.Background())
	if err != nil {
		return false, err
	}
	kept, ok, err := GenerationKeeper.Get()
	switch {
	case errors.Is(err, ErrKeychainSlow):
		return false, nil
	case err != nil || !ok:
		// a store whose key is in the keychain always has its number there:
		// a missing or unreadable one was removed or changed
		why := "has no change count in the keychain"
		if err != nil {
			why = "has a change count in the keychain that cannot be read (" + err.Error() + ")"
		}
		if AllowOldCopy {
			return true, nil
		}
		return false, oldCopyErr(have, 0, why)
	case have < kept:
		if AllowOldCopy {
			return true, nil
		}
		return false, oldCopyErr(have, kept, fmt.Sprintf("is an older copy (change %d) than this computer's keychain remembers (change %d)", have, kept))
	case have > kept:
		_ = GenerationKeeper.Set(have)
	}
	return false, nil
}

// raiseGeneration is the store's hook after a commit that changed data:
// it only ever raises the keychain's number, and only while the store's
// key is still in the keychain.
func raiseGeneration(n uint64) {
	meta, err := sealdb.Peek(context.Background(), DBPath())
	if err != nil || !guarded(meta) {
		return
	}
	if kept, ok, err := GenerationKeeper.Get(); err == nil && ok && kept >= n {
		return
	}
	_ = GenerationKeeper.Set(n)
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
	from, _, _ = GenerationKeeper.Get()
	return from, GenerationKeeper.Set(have)
}

// CopyState says how this home's store compares with the keychain:
// guarded is false when its key is not in the keychain (no protection);
// slow when the keychain did not answer, so nothing was compared.
func CopyState() (have, kept uint64, guardedStore, old bool, err error) {
	meta, err := sealdb.Peek(context.Background(), DBPath())
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
	kept, ok, err := GenerationKeeper.Get()
	if err != nil {
		return have, 0, true, !errors.Is(err, ErrKeychainSlow), err
	}
	if !ok {
		return have, 0, true, true, nil
	}
	return have, kept, true, have < kept, nil
}
