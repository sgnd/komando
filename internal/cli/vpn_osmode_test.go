package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// A VPN saved with the removed OpenVPN OS mode is never run another way:
// vpn up stops with VPN_OS_MODE_REMOVED and says how to add it again, and
// adding it again with --overwrite makes it a built-in client VPN.
func TestVpnOSModeRemoved(t *testing.T) {
	secretHome(t)
	profile := filepath.Join(t.TempDir(), "office.ovpn")
	if err := os.WriteFile(profile, []byte(testProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	add := []string{"vpn", "add", "office", "openvpn", "--config", profile, "--check", "10.8.0.1:22", "--user", "alice", "--password-ref", "secret:db-pass"}
	mustRun(t, add...)
	if _, e := cliRun(t, append(add, "--overwrite", "--os-mode")...); e == nil {
		t.Fatal("--os-mode is still accepted")
	}
	if err := store.Update(store.Save, func(s *store.State) error { s.Vpns["office"].OSMode = true; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"vpn", "up", "office"}, {"vpn", "up", "office", "--dry-run"}} {
		e := wantCode(t, "VPN_OS_MODE_REMOVED", args...)
		if !strings.Contains(e.Hint, "komando vpn add office openvpn") || !strings.Contains(e.Hint, "--overwrite") {
			t.Errorf("%v: hint %q", args, e.Hint)
		}
	}
	mustRun(t, append(add, "--overwrite")...)
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Vpns["office"].OSMode {
		t.Error("added again, the VPN still has OS mode")
	}
}
