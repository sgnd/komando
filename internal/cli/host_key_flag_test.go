package cli

import (
	"testing"
)

// --host-key-policy takes only accept-new, strict or off (any case), and
// never loosens the setting host_key_policy without a person's yes: under
// strict, an agent's --host-key-policy accept-new would pin a first key
// that strict says a person must trust.
func TestHostKeyPolicyFlag(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@192.0.2.10")
	wantCode(t, "USAGE", "--host-key-policy", "bogus", "list")
	mustRun(t, "--host-key-policy", "STRICT", "list")
	if tcl.flags.hostKeyPolicy != "strict" {
		t.Fatalf("flag kept as %q", tcl.flags.hostKeyPolicy)
	}
	noAgent(t)
	mustRun(t, "config", "set", "host_key_policy", "strict")
	n := asAgent(t, false, true)
	wantCode(t, "SAFETY_SETTING", "--host-key-policy", "accept-new", "list")
	wantCode(t, "SAFETY_SETTING", "--host-key-policy", "off", "list")
	mustRun(t, "--host-key-policy", "strict", "list") // as strict: nothing to ask
	if *n != 0 {
		t.Fatalf("windows without --yes: %d", *n)
	}
	// an agent's dry run reads with the setting, and says what it needs
	d, e := invRun(t, "--host-key-policy", "accept-new", "list", "--dry-run")
	if e != nil || tcl.flags.hostKeyPolicy != "" {
		t.Fatalf("dry run: %v %+v, flag %q", d, e, tcl.flags.hostKeyPolicy)
	}
	// the person says yes
	asAgent(t, true, true)
	mustRun(t, "--host-key-policy", "accept-new", "list", "--yes")
	// tightening, or the same, never asks
	noAgent(t)
	mustRun(t, "config", "set", "host_key_policy", "accept-new", "--yes")
	asAgent(t, false, true)
	mustRun(t, "--host-key-policy", "accept-new", "list")
	mustRun(t, "--host-key-policy", "strict", "list")
}
