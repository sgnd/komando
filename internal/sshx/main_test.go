package sshx

import (
	"os"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/testhome"
)

// TestMain keeps the tests away from the keychain of whoever runs them
// (a new home keeps its store key in store.key).
func TestMain(m *testing.M) {
	// no test of this package sees the real home folder (internal/testhome)
	homeDone := testhome.Use()
	os.Setenv("KOMANDO_KEYCHAIN", "off")
	// the account's home follows HOME, so no test reads the real ~/.ssh,
	// also when an AI agent runs the tests
	store.AccountHome = os.UserHomeDir
	code := m.Run()
	homeDone()
	os.Exit(code)
}
