package sshx

import (
	"os"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// TestMain keeps the tests away from the keychain of whoever runs them
// (a new home keeps its store key in store.key).
func TestMain(m *testing.M) {
	os.Setenv("KOMANDO_KEYCHAIN", "off")
	// the account's home follows HOME, so no test reads the real ~/.ssh,
	// also when an AI agent runs the tests
	store.AccountHome = os.UserHomeDir
	os.Exit(m.Run())
}
