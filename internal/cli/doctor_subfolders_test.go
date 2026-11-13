//go:build !windows

package cli

import (
	"os"
	"slices"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// doctor finds a VPN, login or tunnel folder, or a log in it, that other
// users can read.
func TestDoctorSeesLooseSubfolders(t *testing.T) {
	invHome(t)
	if err := store.MkdirPrivate("tunnels"); err != nil {
		t.Fatal(err)
	}
	log := store.Path("tunnels", "t1.log")
	os.WriteFile(log, []byte("x"), 0o644)
	if l := looseFiles(); !slices.Contains(l, log) {
		t.Errorf("a readable tunnel log is not named: %v", l)
	}
	os.Chmod(log, 0o600)
	os.Chmod(store.Path("tunnels"), 0o755)
	if l := looseFiles(); !slices.Contains(l, store.Path("tunnels")) || slices.Contains(l, log) {
		t.Errorf("loose: %v", l)
	}
}
