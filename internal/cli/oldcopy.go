package cli

import (
	"strconv"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// acceptOldCopy is `doctor --accept-old-copy`: after a restore from a
// backup on purpose, the keychain's number is set back to the store's, so
// komando uses the restored folder. A person at a terminal only, with a
// yes: an agent or a script could otherwise undo the protection.
func acceptOldCopy() error {
	if isAgent() || !interactive() {
		return out.Errf(out.ExitPolicy, "NEEDS_PERSON",
			"a person runs `komando doctor --accept-old-copy` in their own terminal",
			"accepting an older copy of komando's folder is for a person at a terminal")
	}
	have, kept, guarded, old, err := store.CopyState()
	if err != nil && !old {
		return err
	}
	if !guarded || !old {
		out.P.Print("doctor.accept-old-copy", map[string]any{"accepted": false, "note": "nothing to accept: the folder is not older than the keychain remembers"}, nil)
		return nil
	}
	if g.dryRun {
		out.P.Print("doctor.accept-old-copy", map[string]any{"accepted": false, "would_accept": have, "keychain": kept}, nil)
		return nil
	}
	if !confirmYes("komando's folder is an older copy (change " + strconv.FormatUint(have, 10) + ", the keychain remembers " + strconv.FormatUint(kept, 10) + "). Use it from now on?") {
		return policyStop(out.Errf(out.ExitError, "CANCELLED", "nothing was changed in "+store.Home(), "the older copy was not accepted"))
	}
	from, err := store.AcceptOldCopy(have)
	if err != nil {
		return err
	}
	audit(nil, "doctor.accept-old-copy", nil, "", true, map[string]any{"from": from, "to": have})
	out.P.Print("doctor.accept-old-copy", map[string]any{"accepted": true, "from": from, "to": have}, nil)
	return nil
}

// lookAtOldCopy lets this command open an old copy to look at it, until
// the function it returns is called.
func lookAtOldCopy() func() {
	store.AllowOldCopy = true
	return func() { store.AllowOldCopy = false }
}
