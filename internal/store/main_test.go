package store

import (
	"bytes"
	"os"
	"testing"

	"github.com/sgnd/komando/internal/testhome"
)

// TestMain keeps the tests away from the keychain of whoever runs them, and
// gives the store a fixed stand-in key (the vault package owns the real
// ones); tests that count new keys use fakeKeys.
func TestMain(m *testing.M) {
	// no test of this package sees the real home folder (internal/testhome)
	homeDone := testhome.Use()
	os.Setenv("KOMANDO_KEYCHAIN", "off")
	// the account's home follows HOME, so no test reads the real one, also
	// when an AI agent runs the tests
	AccountHome = os.UserHomeDir
	KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
		return bytes.Repeat([]byte{9}, 32), map[string]string{"key_mode": "test"}, nil
	}
	code := m.Run()
	homeDone()
	os.Exit(code)
}
