package cli

import (
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// hostKeyRank orders the host key policies from loosest to strictest; ""
// is the default, accept-new.
var hostKeyRank = map[string]int{"off": 0, "accept-new": 1, "": 1, "strict": 2}

// checkHostKeyFlag takes --host-key-policy: accept-new, strict or off, in
// any case, and nothing else. A flag looser than the setting
// host_key_policy (off always is) needs the same yes as loosening the
// setting with config set.
func checkHostKeyFlag(cl *call) error {
	p := strings.ToLower(cl.flags.hostKeyPolicy)
	if p == "" {
		return nil
	}
	if _, ok := hostKeyRank[p]; !ok {
		return out.Errf(out.ExitUsage, "USAGE", "use --host-key-policy accept-new, strict or off", "--host-key-policy %q is not accept-new, strict or off", cl.flags.hostKeyPolicy)
	}
	cl.flags.hostKeyPolicy = p
	what, err := hostKeyFlagWhat(cl)
	if err != nil || what == "" {
		return err
	}
	if cl.dryRun() && cl.isAgent() {
		// an agent's preview still connects to read; it does that with
		// the setting's identity check, since a dry run never asks the
		// person. People and scripts preview as they run.
		_ = guardSafety(cl, what)
		cl.flags.hostKeyPolicy = ""
		return nil
	}
	return guardSafety(cl, what)
}

// hostKeyFlagWhat is the safety question for a --host-key-policy that is
// looser than the setting host_key_policy, or "" when it is not.
func hostKeyFlagWhat(cl *call) (string, error) {
	p := cl.flags.hostKeyPolicy
	if p == "off" {
		return "--host-key-policy off (no server identity check)", nil
	}
	if p == "" || p == "strict" {
		return "", nil
	}
	st, err := loadState()
	if err != nil {
		return "", err
	}
	set := strings.ToLower(st.Settings.HostKeyPolicy)
	if hostKeyRank[p] < hostKeyRank[set] {
		return "--host-key-policy " + p + " (looser than your setting host_key_policy " + set + ")", nil
	}
	return "", nil
}
