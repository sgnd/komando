package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// TestNotFoundKinds: every kind a command passes to out.NotFound has its
// code, and a server, conn or VPN name komando does not know gives one
// code, TARGET_NOT_FOUND, with the kind kept for the text (C79).
func TestNotFoundKinds(t *testing.T) {
	want := map[string]string{
		"host": "TARGET_NOT_FOUND", "conn": "TARGET_NOT_FOUND", "vpn": "TARGET_NOT_FOUND",
		"key": "SSH_KEY_NOT_FOUND", "job": "JOB_NOT_FOUND", "recipe": "RECIPE_NOT_FOUND",
		"secret": "SECRET_NOT_FOUND", "tunnel": "TUNNEL_NOT_FOUND", "group": "GROUP_NOT_FOUND",
	}
	for k, code := range want {
		e := out.NotFound(k, "x")
		if e.Code != code || e.Exit != out.ExitNotFound {
			t.Errorf("%s: %s %d", k, e.Code, e.Exit)
		}
		if code == "TARGET_NOT_FOUND" && e.Wanted() != k {
			t.Errorf("%s: wanted %q", k, e.Wanted())
		}
	}
}
