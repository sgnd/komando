package runner

import (
	"os"
	"testing"

	"github.com/sgnd/komando/internal/testhome"
)

// TestMain keeps the tests away from the real home folder: the allowlist in
// sandbox.go names HOME and the XDG folders, and a test that ran a command
// would otherwise see the account's own (internal/testhome).
func TestMain(m *testing.M) {
	done := testhome.Use()
	code := m.Run()
	done()
	os.Exit(code)
}
