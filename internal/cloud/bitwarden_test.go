package cloud

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
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

// The server picks the KDF settings: ones Bitwarden does not allow are
// refused quickly; they never run for minutes, panic or wrap to a weak key.
func TestBitwardenKDFBounds(t *testing.T) {
	cases := []struct {
		name            string
		kdf, t, mMiB, p int
	}{
		{"pbkdf2 2^31 iterations", 0, 1 << 31, 0, 0},
		{"pbkdf2 above 2M", 0, 2_000_001, 0, 0},
		{"argon2 p=256 (uint8 0)", 1, 2, 16, 256},
		{"argon2 t=2^32 (uint32 0)", 1, 1 << 32, 16, 1},
		{"argon2 t=2^32+2 (uint32 2)", 1, 1<<32 + 2, 16, 1},
		{"argon2 m=4194304 MiB (uint32 0 KiB)", 1, 2, 4194304, 1},
		{"argon2 m=2048 MiB", 1, 2, 2048, 1},
		{"argon2 t=11", 1, 11, 16, 1},
		{"argon2 p=17", 1, 2, 16, 17},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			start := time.Now()
			if _, err := BitwardenMasterKey("password", "a@b", tc.kdf, tc.t, tc.mMiB, tc.p); err == nil {
				t.Error("accepted")
			}
			if d := time.Since(start); d > time.Second {
				t.Errorf("took %v", d)
			}
		})
	}
	if _, err := BitwardenMasterKey("password", "a@b", 1, 10, 16, 16); err != nil {
		t.Errorf("the highest t and p Bitwarden allows: %v", err)
	}
}
