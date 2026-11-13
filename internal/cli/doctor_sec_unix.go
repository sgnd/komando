//go:build !windows

package cli

import (
	"os"

	"github.com/sgnd/komando/internal/store"
)

// platformChecks: macOS and Linux need no notes beyond the shared ones.
func platformChecks(func(name string, ok, warn bool, detail string)) {}

// privateFix is the commands that make komando's folder and files private.
func privateFix() string { return "chmod 700 " + store.Home() + " && chmod 600 on the files" }

// looseFiles lists komando files that other users on this computer can read.
func looseFiles() []string {
	var loose []string
	check := func(p string) {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
			loose = append(loose, p)
		}
	}
	check(store.Home())
	for _, f := range []string{"runtime.json", "runtime.pids", store.StoreFile, store.StoreFile + "-journal", "store.key"} {
		check(store.Path(f))
	}
	return loose
}
