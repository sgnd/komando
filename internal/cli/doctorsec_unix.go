//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// platformChecks: macOS and Linux need no notes beyond the shared ones.
func platformChecks(func(name string, ok, warn bool, detail string)) {}

// looseFiles lists komando files that other users on this computer can read.
func looseFiles() []string {
	var loose []string
	check := func(p string) {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
			loose = append(loose, p)
		}
	}
	check(store.Home())
	for _, f := range []string{"state.json", "runtime.json", "vault.json", "vault.key", "audit.jsonl", "known_hosts", store.StoreFile, store.StoreFile + "-journal", "store.key"} {
		check(store.Path(f))
	}
	keys, _ := filepath.Glob(store.Path("keys", "*"))
	for _, k := range keys {
		if !strings.HasSuffix(k, ".pub") {
			check(k)
		}
	}
	return loose
}
