//go:build e2elab

package store

import "testing"

// A komando built for the e2e lab takes the account's home folder from
// KOMANDO_E2E_ACCOUNT_HOME.
func TestLabAccountHome(t *testing.T) {
	saved := AccountHome
	t.Cleanup(func() { AccountHome = saved })
	dir := t.TempDir()
	t.Setenv("KOMANDO_E2E_ACCOUNT_HOME", dir)
	useLabHome()
	if d, err := AccountHome(); err != nil || d != dir {
		t.Fatalf("AccountHome() = %q, %v, want %q", d, err, dir)
	}
}
