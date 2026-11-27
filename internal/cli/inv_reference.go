package cli

import (
	"maps"
	"slices"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Owner O-09: a reference is spelled credential:NAME and the marker in
// text for a file {{credential:NAME}}. The spellings of format 2 are never
// read: each place that takes a reference stops on them with BAD_REFERENCE
// and a hint that names the new spelling. Only the store package knows the
// old spellings (the migration and the F10 check live there).

// oldRef is the stop for ref given as what (a flag, an option) when it is
// in the spelling of format 2; nil otherwise.
func oldRef(what, ref string) error {
	if _, old := store.OldReference(ref); old {
		return store.OldRefError(what, ref)
	}
	return nil
}

// checkEnv checks environment variables: shell names, because they are
// exported on the remote side unquoted, and no value in the reference
// spelling of format 2.
func checkEnv(m map[string]string) error {
	if err := oldEnvRefs(m); err != nil {
		return err
	}
	for k := range m {
		if !sshx.ValidEnvKey(k) {
			return out.Usage("environment variable name %q is not valid: use letters, digits and _, not starting with a digit", k)
		}
	}
	return nil
}

// oldEnvRefs stops on an environment value in the spelling of format 2.
func oldEnvRefs(env map[string]string) error {
	for _, k := range slices.Sorted(maps.Keys(env)) {
		if err := oldRef("--env "+k, env[k]); err != nil {
			return err
		}
	}
	return nil
}

// oldMarker stops text for a file that holds the marker of format 2
// (Audit E1-3): it is never written as it is.
func oldMarker(what, text string) error {
	if m, old := store.OldMarker(text); old {
		return out.Errf(out.ExitUsage, "BAD_REFERENCE",
			"write "+m+": komando puts a credential's value into a file only for {{credential:NAME}}",
			"%s holds the old marker of a secret, which komando no longer reads; nothing was written", what)
	}
	return nil
}
