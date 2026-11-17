//go:build !windows

package store

import "os"

// privateHome does nothing here: the folder's mode, 0700, keeps it private.
func privateHome(string) error { return nil }

// tightenHome makes a komando folder that was already there private again
// (0700) when others may read or enter it (a copy, an unzip, a chmod),
// as long as it is komando's: it holds the store or its key. Any other
// folder KOMANDO_HOME names is left as it is; doctor reports it.
func tightenHome(h string) {
	fi, err := os.Lstat(h)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 == 0 {
		return
	}
	for _, f := range []string{StoreFile, "store.key"} {
		if _, err := os.Lstat(Path(f)); err == nil {
			_ = os.Chmod(h, 0o700)
			return
		}
	}
}
