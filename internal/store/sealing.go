package store

import (
	"errors"
	"os"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// While `komando seal` moves a folder of before, its store is built under
// another name, so other komando processes keep using the files of before
// (and wait on their locks, which the move holds) until the store is whole
// and checked. Only this process sees it, as its sealed store.

var (
	sealMu   sync.Mutex
	sealing  bool
	sealHeld = map[string]bool{} // locks the move holds: Lock passes for them in this process
	madeKey  bool                // the move made store.key
)

const sealingFile = ".store.db.sealing"

// DBPath is the file of this home's sealed store (another one while a move
// builds it).
func DBPath() string {
	sealMu.Lock()
	defer sealMu.Unlock()
	if sealing {
		return Path(sealingFile)
	}
	return Path(StoreFile)
}

func isSealing() bool {
	sealMu.Lock()
	defer sealMu.Unlock()
	return sealing
}

func heldBySeal(name string) bool {
	sealMu.Lock()
	defer sealMu.Unlock()
	return sealHeld[name]
}

// sealLocks are the file backend's locks: every writer of the files of
// before takes one of them.
var sealLocks = []string{".lock", runtimeLock, ".vault.lock", ".known_hosts.lock"}

// BeginSeal takes the file backend's locks for the whole move (the files
// of before are read under them); StartBuilding then turns this process to
// a store under a building name. EndSeal undoes both.
func BeginSeal() error {
	var unlocks []func()
	for _, l := range sealLocks {
		u, err := Lock(l)
		if err != nil {
			for _, f := range unlocks {
				f()
			}
			return err
		}
		unlocks = append(unlocks, u)
	}
	sealMu.Lock()
	for _, l := range sealLocks {
		sealHeld[l] = true
	}
	releaseSeal = func() {
		for i := len(unlocks) - 1; i >= 0; i-- {
			unlocks[i]()
		}
	}
	sealMu.Unlock()
	closeDBs()
	return nil
}

var releaseSeal func()

// StartBuilding turns this process to the store being built.
func StartBuilding() {
	_ = os.Remove(Path(sealingFile)) // a move that crashed earlier
	_, err := os.Stat(Path("store.key"))
	sealMu.Lock()
	sealing, madeKey = true, errors.Is(err, os.ErrNotExist)
	sealMu.Unlock()
	closeDBs()
}

// FinishSeal puts the built store in place: from now on every komando
// process uses it. The locks stay until EndSeal.
func FinishSeal() error {
	closeDBs()
	if err := os.Rename(Path(sealingFile), Path(StoreFile)); err != nil {
		return err
	}
	sealMu.Lock()
	sealing = false
	sealMu.Unlock()
	return nil
}

// AbortSeal sets a store that was being built aside, with its key file,
// under names of their own, and forgets its change count.
func AbortSeal() {
	closeDBs()
	ts := time.Now().UTC().Format("20060102T150405")
	_ = os.Rename(Path(sealingFile), Path(StoreFile+".failed-"+ts))
	sealMu.Lock()
	made := madeKey
	sealing = false
	sealMu.Unlock()
	if made {
		_ = os.Rename(Path("store.key"), Path("store.key.failed-"+ts))
	}
	if GenerationKeeper.Del != nil {
		GenerationKeeper.Del()
	}
}

// EndSeal lets go of the locks BeginSeal took.
func EndSeal() {
	sealMu.Lock()
	for _, l := range sealLocks {
		delete(sealHeld, l)
	}
	sealing = false
	r := releaseSeal
	releaseSeal = nil
	sealMu.Unlock()
	closeDBs()
	if r != nil {
		r()
	}
}

// missingStore: the files of before are notes of a move, but store.db is
// gone. Starting empty would drop every protected server and rule.
func missingStore() error {
	if !IsMovedNote(Path("state.json")) {
		return nil
	}
	return out.Errf(out.ExitError, "STATE_CORRUPT",
		"put store.db back from a backup, or run `komando seal --undo` to go back to the files of before (they are in before-seal.archive)",
		"%s is missing, though this folder was sealed", Path(StoreFile))
}
