package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// Logs of tunnels, logins and VPNs that ended a week ago go; a log
// something running writes to, a newer one and other files stay.
func TestSweepLogs(t *testing.T) {
	invHome(t)
	if err := store.MkdirPrivate("tunnels"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	mk := func(name string, mod time.Time) string {
		p := store.Path("tunnels", name)
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chtimes(p, mod, mod)
		return p
	}
	gone := mk("t-old.log", old)
	live := mk("t-live.log", old)
	recent := mk("t-new.log", time.Now())
	other := mk("state.json", old)
	sweepLogs("tunnels", map[string]bool{filepath.Clean(live): true})
	for p, want := range map[string]bool{gone: false, live: true, recent: true, other: true} {
		if _, err := os.Stat(p); (err == nil) != want {
			t.Errorf("%s: there %v, want %v", filepath.Base(p), err == nil, want)
		}
	}
	st := &store.State{Tunnels: map[string]*store.Tunnel{"t1": {LogFile: live}}}
	if !liveLogs(st)[filepath.Clean(live)] {
		t.Error("liveLogs misses a tunnel's log")
	}
}
