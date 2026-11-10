package sshx

import (
	"github.com/sgnd/komando/internal/store"
	"os"
	"testing"
)

// TestMain keeps the tests away from the keychain of whoever runs them,
// and on the file backend unless KOMANDO_TEST_SEALED=1 (CI runs both).
func TestMain(m *testing.M) {
	os.Setenv("KOMANDO_KEYCHAIN", "off")
	store.UseSealedForNewHomes(os.Getenv("KOMANDO_TEST_SEALED") == "1")
	os.Exit(m.Run())
}
