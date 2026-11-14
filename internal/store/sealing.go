package store

import (
	"bytes"
	"io"
	"os"

	"github.com/sgnd/komando/internal/out"
)

// DBPath is the file of this home's sealed store.
func DBPath() string { return Path(StoreFile) }

// storeMade is the file komando writes in its folder when it makes a
// store there (createDB), and when it opens a store made before komando
// wrote it (openDB). It stays for the life of the folder: komando removes
// it only with a store it made and did not keep (createDB), and when a
// person starts an empty store on purpose (AcceptOldCopy). It is the one
// trace every store leaves, a store whose key is in the keychain too
// (that one has no store.key). A refused attempt never writes it: only a
// store that was made or opened does.
const storeMade = "store.made"

// storeMadeNote is what storeMade holds, for a person who finds it.
const storeMadeNote = "komando made a store in this folder. While this file is here, komando does not start an empty store where store.db went missing: put store.db back from a backup.\n"

// markStoreMade writes storeMade when it is not there; made: this call
// wrote it.
func markStoreMade() (made bool, err error) {
	p := Path(storeMade)
	if _, err := os.Lstat(p); err == nil {
		return false, nil
	}
	if err := WriteFileAtomic(p, []byte(storeMadeNote), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// storeTraces are the files only a store leaves in its folder: storeMade,
// its key file (and one being changed), SQLite's journal of store.db, and
// the runtime files kept beside it. The audit log is inside store.db. The
// lock files are not traces: komando makes .store.lock before it makes a
// store, and an attempt that was refused leaves it behind. Nor is
// store.db.new: a store being made, never moved into place.
var storeTraces = []string{storeMade, "store.key", "store.key.new", StoreFile + "-journal", "runtime.pids"}

// storeTrace names a file that shows this home had a store, or "". A
// runtime.json counts only when it is sealed (with the store's key): a
// plain one is never komando's own.
func storeTrace() string {
	for _, f := range storeTraces {
		if _, err := os.Lstat(Path(f)); err == nil {
			return f
		}
	}
	if f, err := os.Open(runtimePath()); err == nil {
		head := make([]byte, len(runtimeMagic))
		_, rerr := io.ReadFull(f, head)
		f.Close()
		if rerr == nil && bytes.Equal(head, runtimeMagic) {
			return "runtime.json"
		}
	}
	return ""
}

// sealedSign names what shows this home had a store, or "": a trace
// (storeTrace), or a change count the keychain keeps for this home.
func sealedSign() string {
	if f := storeTrace(); f != "" {
		return f
	}
	// the keychain only for a folder that holds something: a fresh, empty
	// one is asked nothing (a keychain call can be slow or prompt)
	if ents, _ := os.ReadDir(Home()); len(ents) > 0 && GenerationKeeper.Get != nil {
		if _, ok, err := probeCount(); err == nil && ok {
			return "the keychain's change count"
		}
	}
	return ""
}

// missingStore: this home had a store, but store.db is gone. Starting
// empty would drop every protected server and rule.
func missingStore() error {
	sign := sealedSign()
	if sign == "" {
		return nil
	}
	return out.Errf(out.ExitError, "STATE_CORRUPT",
		"put store.db back from a backup",
		"%s is missing, though this folder had a store (%s)", Path(StoreFile), sign)
}
