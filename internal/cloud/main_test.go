package cloud

import (
	"os"
	"testing"
)

// TestMain keeps the tests away from the keychain of whoever runs them
// (a new home keeps its store key in store.key).
func TestMain(m *testing.M) {
	os.Setenv("KOMANDO_KEYCHAIN", "off")
	os.Exit(m.Run())
}
