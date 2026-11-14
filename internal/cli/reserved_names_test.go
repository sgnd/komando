package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// The cloud names are reserved for every kind a target names (S-1.5,
// C-V24): no new server, conn or VPN takes aws, gcp or azure, by add or
// rename. An older entry with such a name keeps working; `login aws`
// stays the cloud login and says so on stderr, and doctor warns.
func TestReservedCloudNames(t *testing.T) {
	invHome(t)
	for _, args := range [][]string{
		{"host", "add", "aws", "u@127.0.0.1:1"},
		{"conn", "add", "gcp", "redis://127.0.0.1:1/0"},
		{"conn", "add", "Azure", "redis://127.0.0.1:1/0"},
		{"vpn", "add", "AWS", "socks", "--proxy-address", "127.0.0.1:1080"},
	} {
		e := wantCode(t, "USAGE", args...)
		if !strings.Contains(e.Message, "cloud login") || !strings.Contains(e.Hint, "-1") {
			t.Errorf("%v: %+v", args, e)
		}
	}
	mustRun(t, "conn", "add", "c1", "redis://127.0.0.1:1/0")
	wantCode(t, "USAGE", "conn", "rename", "c1", "aws")
	wantCode(t, "USAGE", "rename", "c1", "gcp")

	// an entry from before the names were reserved
	if err := store.Update(store.Save, func(s *store.State) error {
		s.Hosts["aws"] = &store.Host{Name: "aws", Address: "127.0.0.1", Port: 1, User: "u", CreatedAt: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, text := runMain(t, "login", "aws", "--dry-run", "--profile", "komando-test-none")
	if !strings.Contains(text, "`komando host rename aws NEW`") {
		t.Errorf("login aws: no note about the server named aws: %s", text)
	}
	_, text = runMain(t, "doctor")
	if !strings.Contains(text, `"name":"host:aws","ok":true,"warning":true`) || !strings.Contains(text, "komando host rename aws NEW") {
		t.Errorf("doctor: %s", text)
	}
}
