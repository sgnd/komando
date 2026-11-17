//go:build !windows

package cli

import (
	"os"

	"github.com/sgnd/komando/internal/store"
)

// platformChecks: macOS and Linux need no notes beyond the shared ones.
func platformChecks(*call, func(name string, ok, warn bool, detail string)) {}

// privateFix is the commands that make komando's folder and files private.
func privateFix() string {
	return "chmod -R go-rwx " + store.Home() + " (only you may read and write komando's folder and everything in it)"
}

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
	// the folders of VPN, login and tunnel logs and state, and what is in
	// them: a log can hold addresses and errors, a VPN's state its session
	for _, d := range []string{"vpn", "login", "tunnels"} {
		check(store.Path(d))
		ents, _ := os.ReadDir(store.Path(d))
		for _, e := range ents {
			if e.Type().IsRegular() || e.IsDir() {
				check(store.Path(d, e.Name()))
			}
		}
	}
	return loose
}
