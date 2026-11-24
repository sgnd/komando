package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// The stop for a name another server, conn or VPN already has, pinned before
// it moves to internal/inventory: code, exit, message and hint.
func TestNameTaken(t *testing.T) {
	e := toErr(nameTaken("conn", "pg"))
	if e.Code != "NAME_TAKEN" || e.Exit != out.ExitConflict {
		t.Errorf("code %q, exit %d", e.Code, e.Exit)
	}
	if want := `name "pg" is already used by a ` + out.KindWord("conn"); e.Message != want {
		t.Errorf("message %q, want %q", e.Message, want)
	}
	if want := "pick another name; servers, conns and VPNs share one name space (see `komando conn show pg`)"; e.Hint != want {
		t.Errorf("hint %q, want %q", e.Hint, want)
	}
}
