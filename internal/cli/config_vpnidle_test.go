package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// vpn_idle 0 keeps a VPN up until it is stopped, and a longer time keeps
// it up longer: both weaken a safety check, so an AI agent needs a
// person's yes; a shorter time is fine for anyone.
func TestVpnIdleIsASafetySetting(t *testing.T) {
	invHome(t)
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	mustRun(t, "config", "set", "vpn_idle", "10m") // shorter than 30m
	for _, v := range []string{"0", "off", "2h"} {
		if e := wantCode(t, "SAFETY_SETTING", "config", "set", "vpn_idle", v); e.Exit != out.ExitPolicy {
			t.Errorf("%s: exit %d", v, e.Exit)
		}
	}
	mustRun(t, "config", "set", "vpn_idle", "10m") // the same: nothing to ask
}
