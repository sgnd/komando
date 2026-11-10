package store

import (
	"os"
	"testing"
)

// TestMain keeps the tests away from the keychain of whoever runs them, and
// on the file backend: this package's sealed tests (sealed_test.go,
// backend_test.go) turn the store on themselves, with a stand-in key.
func TestMain(m *testing.M) {
	os.Setenv("KOMANDO_KEYCHAIN", "off")
	UseSealedForNewHomes(false)
	os.Exit(m.Run())
}
