package cli

import (
	"fmt"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// carryMetaSeal gives a store made before the sealed copy of its settings
// row the copy, after a person's command at a terminal opened it. An AI
// agent's or a script's command never writes it: doctor tells them a
// person's command does it (C08).
func carryMetaSeal(cl *call) {
	if cl.isAgent() || !cl.interactive() || cl.flags.dryRun {
		return
	}
	if wrote, err := store.SealMeta(); err == nil && wrote {
		fmt.Fprintln(cl.out.Err, "komando: sealed the store's settings row (key mode, salt, scrypt cost), once: a change to it made outside komando is now noticed")
	}
}

// metaSealCheck is doctor's line about the sealed copy of the settings row.
func metaSealCheck(add func(name string, ok, warn bool, detail string)) {
	have, err := store.MetaSealed()
	switch {
	case err != nil:
		return // the vault line says why the store does not open
	case !have:
		add("store_meta", false, true, "the settings row of "+store.StoreFile+" (key mode, salt, scrypt cost) is not sealed yet, so a change to it made outside komando would not be noticed: run any komando command in your own terminal once")
	default:
		add("store_meta", true, false, "the settings row of "+store.StoreFile+" is sealed: a change made outside komando is noticed")
	}
}

// resealMeta is `doctor --reseal-meta`: after STATE_CORRUPT for a changed
// settings row, a person checks the store with their key and seals the row
// again. A person at a terminal only.
func resealMeta(cl *call) error {
	if cl.isAgent() || !cl.interactive() {
		return out.Errf(out.ExitPolicy, "NEEDS_PERSON",
			"a person runs `komando doctor --reseal-meta` in their own terminal",
			"sealing the store's settings row again is for a person at a terminal").NoFlag()
	}
	if cl.flags.dryRun {
		cl.out.Print("doctor.reseal-meta", map[string]any{"resealed": false, "note": "the real run opens the store with your key, checks every record and seals the settings row again"}, nil)
		return nil
	}
	if !confirmYes(cl, "Open "+store.StoreFile+" with your key, check every record, and seal its settings row (key mode, salt, scrypt cost) as it is now?") {
		return cl.policyStop(out.Errf(out.ExitError, "CANCELLED", "run `komando doctor --reseal-meta` again to be asked again", "%s", "nothing was changed in "+store.Home()))
	}
	meta, err := store.ResealMeta()
	if err != nil {
		return out.Errf(out.ExitError, "STATE_CORRUPT", "the key does not open every record: restore the komando folder from a backup", "nothing was changed: %v", err)
	}
	kept := map[string]any{"key_mode": meta["key_mode"], "scrypt_n": meta["scrypt_n"]}
	audit(cl, nil, "doctor.reseal-meta", nil, "", true, kept)
	cl.out.Print("doctor.reseal-meta", map[string]any{"resealed": true, "kept": kept}, nil)
	return nil
}

// storeOpens checks that the store opens with its key before doctor
// reports the key mode and scrypt cost its readable settings row names. A
// passphrase store with no passphrase here is reported as it is.
func storeOpens(s vault.Strength) error {
	if s.Mode == "passphrase" && vault.Passphrase() == "" {
		return nil
	}
	_, err := store.MetaSealed()
	return err
}
