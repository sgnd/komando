package store

import (
	"bytes"
	"os"
	"testing"
)

// TestMain keeps the tests away from the keychain of whoever runs them, and
// gives the store a fixed stand-in key (the vault package owns the real
// ones); tests that count new keys use fakeKeys.
func TestMain(m *testing.M) {
	os.Setenv("KOMANDO_KEYCHAIN", "off")
	KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
		return bytes.Repeat([]byte{9}, 32), map[string]string{"key_mode": "test"}, nil
	}
	os.Exit(m.Run())
}
