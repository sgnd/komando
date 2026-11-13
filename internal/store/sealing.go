package store

import (
	"os"

	"github.com/sgnd/komando/internal/out"
)

// DBPath is the file of this home's sealed store.
func DBPath() string { return Path(StoreFile) }

// sealedSign names what shows this home had a store, or "": the store's
// key file, runtime.pids, or a change count the keychain keeps for this
// home.
func sealedSign() string {
	for _, f := range []string{"store.key", "runtime.pids"} {
		if _, err := os.Stat(Path(f)); err == nil {
			return f
		}
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
