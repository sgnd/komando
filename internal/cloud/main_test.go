package cloud

import (
	"os"
	"testing"

	"github.com/sgnd/komando/internal/testhome"
)

// TestMain keeps the tests away from the keychain of whoever runs them
// (a new home keeps its store key in store.key).
func TestMain(m *testing.M) {
	// no test of this package sees the real home folder (internal/testhome)
	homeDone := testhome.Use()
	os.Setenv("KOMANDO_KEYCHAIN", "off")
	code := m.Run()
	homeDone()
	os.Exit(code)
}
