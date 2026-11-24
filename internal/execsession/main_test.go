package execsession

import (
	"os"
	"testing"

	"github.com/sgnd/komando/internal/testhome"
)

// No test of this package sees the real home folder (internal/testhome).
func TestMain(m *testing.M) {
	homeDone := testhome.Use()
	code := m.Run()
	homeDone()
	os.Exit(code)
}
