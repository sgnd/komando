package cli

import (
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func init() {
	// a host key pinned on first use goes into the audit log with its
	// fingerprint (sshx tells the person on stderr)
	sshx.HostKeyPinned = auditPinnedKey
}

// auditPinnedKey records a host key komando trusted the first time it
// reached the server, so it can be checked later (`komando audit`).
func auditPinnedKey(k sshx.NewHostKey) {
	st, err := store.Load()
	if err != nil {
		st = nil // the audit log is written either way
	}
	audit(st, "host.key-pinned", []string{k.Host}, "", true,
		map[string]any{"address": k.Address, "key_type": k.Type, "fingerprint": k.Fingerprint, "first_use": true})
}
