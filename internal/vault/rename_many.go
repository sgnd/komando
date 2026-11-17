package vault

import (
	"crypto/rand"
	"fmt"
	"maps"
	"slices"

	"github.com/sgnd/komando/internal/store"
)

// reservedName is the secret komando keeps for its approval code (the
// CLI's approvalSecret). A person sets it with `komando config
// approval-code`; no rename may move it away or put another value under
// its name.
const reservedName = "komando-approval-totp"

// RenameMany moves the values of several secrets to new names (pairs maps
// old to new) in one change of the vault: every secret moves, or none
// does. Values are decrypted and sealed again inside this package and
// never leave it, as in Rename.
//
// A new name may not exist yet, and may not be a name that moves too: a
// swap (a→b, b→a) or a chain (a→b, b→c) is refused, because a reference
// the caller does not rewrite (a {{secret:b}} already in a file on a
// server) would then quietly get another secret's value. Two old names
// may not share a new one, and the approval code's secret never moves.
func RenameMany(w store.Write, pairs map[string]string) error {
	if len(pairs) == 0 {
		return nil
	}
	if err := checkRenames(pairs); err != nil {
		return err
	}
	return change(w, func(f *file) error {
		for _, from := range slices.Sorted(maps.Keys(pairs)) {
			to := pairs[from]
			if _, ok := f.Entries[from]; !ok {
				return fmt.Errorf("%w: %s", ErrNotFound, from)
			}
			if _, ok := f.Entries[to]; ok {
				return fmt.Errorf("%w: %s", ErrExists, to)
			}
		}
		a, err := f.aead()
		if err != nil {
			return err
		}
		plain := make(map[string][]byte, len(pairs))
		defer func() {
			for _, pt := range plain {
				clear(pt)
			}
		}()
		for from := range pairs {
			e := f.Entries[from]
			pt, err := a.Open(nil, e.Nonce, e.Data, []byte(from))
			if err != nil {
				return fmt.Errorf("cannot decrypt secret %q (wrong KOMANDO_VAULT_PASS or store.key?)", from)
			}
			plain[from] = pt
		}
		moved := make(map[string]*entry, len(pairs))
		for from, to := range pairs {
			nonce := make([]byte, a.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			// the values did not change, so neither does their UpdatedAt
			moved[to] = &entry{Nonce: nonce, Data: a.Seal(nil, nonce, plain[from], []byte(to)), UpdatedAt: f.Entries[from].UpdatedAt}
		}
		for from := range pairs {
			delete(f.Entries, from)
		}
		for to, e := range moved {
			f.Entries[to] = e
		}
		return nil
	})
}

// checkRenames refuses what RenameMany never does, before the vault is
// opened: an empty or unchanged name, the reserved secret, a swap or chain,
// and two old names with one new name.
func checkRenames(pairs map[string]string) error {
	seen := make(map[string]string, len(pairs))
	for _, from := range slices.Sorted(maps.Keys(pairs)) {
		to := pairs[from]
		switch {
		case from == "" || to == "":
			return fmt.Errorf("a secret name cannot be empty")
		case from == to:
			return fmt.Errorf("secret %q: the old and the new name are the same", from)
		case from == reservedName || to == reservedName:
			return fmt.Errorf("secret %s belongs to komando's approval code and cannot be renamed or replaced", reservedName)
		}
		if _, moves := pairs[to]; moves {
			return fmt.Errorf("secret %q would move to %q, which moves too; rename them in two steps", from, to)
		}
		if other, ok := seen[to]; ok {
			return fmt.Errorf("secrets %q and %q would both be named %q", other, from, to)
		}
		seen[to] = from
	}
	return nil
}
