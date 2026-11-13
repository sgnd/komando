// Package tmpclean keeps the temporary files and folders this komando run
// made (a download before its rename, a sign-in browser profile, a
// database CA copy), so a hard stop still removes them. Each one is
// removed by its own code when it is done; the list is for the second
// Ctrl-C (or SIGTERM, SIGHUP), which ends komando without running that
// code. Old leftovers of a run that was killed outright (SIGKILL, a power
// cut) are swept by Sweep where such files are made.
package tmpclean

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	mu    sync.Mutex
	paths = map[int]string{}
	next  int
)

// Add keeps path (a file or a folder) on the list. The returned forget
// takes it off: call it once the path is removed or renamed into place.
func Add(path string) (forget func()) {
	mu.Lock()
	defer mu.Unlock()
	next++
	id := next
	paths[id] = path
	return func() {
		mu.Lock()
		delete(paths, id)
		mu.Unlock()
	}
}

// RemoveAll removes every path on the list and empties it.
func RemoveAll() {
	mu.Lock()
	defer mu.Unlock()
	for id, p := range paths {
		_ = os.RemoveAll(p)
		delete(paths, id)
	}
}

// Kept is how many paths are on the list (tests).
func Kept() int {
	mu.Lock()
	defer mu.Unlock()
	return len(paths)
}

// Stale is how old a leftover must be before Sweep removes it: a run that
// is still going (a slow sign-in, a long download) is never that old.
const Stale = 24 * time.Hour

// Sweep removes what earlier runs left in dir: names that start with
// prefix and end with suffix, owned by this user (a folder anyone can
// write to, like /tmp, holds other users' files too), changed more than
// Stale ago. Links are removed, never followed.
func Sweep(dir, prefix, suffix string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, suffix) || len(n) <= len(prefix)+len(suffix) {
			continue
		}
		p := filepath.Join(dir, n)
		fi, err := os.Lstat(p)
		if err != nil || time.Since(fi.ModTime()) < Stale || !mine(fi) {
			continue
		}
		_ = os.RemoveAll(p)
	}
}
