package cloud

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The device id lives in KOMANDO_HOME like every other state file, and
// stays the same between runs.
func TestBwDeviceIDHonoursKomandoHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "state")
	t.Setenv("KOMANDO_HOME", home)
	t.Setenv("HOME", t.TempDir())

	id := bwDeviceID()
	if id == "" || id == "komando" {
		t.Fatalf("id = %q", id)
	}
	p := filepath.Join(home, "bitwarden-device")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("device file not in KOMANDO_HOME: %v", err)
	}
	if string(b) != id {
		t.Fatalf("file has %q, want %q", b, id)
	}
	if again := bwDeviceID(); again != id {
		t.Fatalf("second call = %q, want %q", again, id)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(home); fi.Mode().Perm() != 0o700 {
			t.Errorf("folder mode = %v, want 0700", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %v, want 0600", fi.Mode().Perm())
		}
	}
}
