//go:build windows

package cli

import (
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// platformChecks are doctor's notes about what Windows lacks: the
// Credential Manager for the vault key, and a desktop for the approval
// window.
func platformChecks(cl *call, add func(name string, ok, warn bool, detail string)) {
	if _, err := vault.KeychainTool(); err != nil {
		add("keychain", false, true, "no Windows Credential Manager here ("+err.Error()+"): the vault key stays in store.key unless you set a passphrase with `komando secret passphrase`")
	}
	if cl.getenv("KOMANDO_NO_DIALOG") == "" && !interactiveDesktop() {
		add("approval_window", false, true, "komando cannot show its \"Allow once\" window here (no desktop session, a service or a remote shell): an AI agent's --yes, --allow-dangerous and --reveal stop, and a person runs those commands in their own terminal")
	}
}

// looseFiles lists komando's folder and the files inside that someone
// else may open: Windows decides that by access lists, not file modes.
func looseFiles() []string { return store.LooseFiles() }

// privateFix is the commands that give komando's folder its own access
// list again and make everything inside take it over.
func privateFix() string { return store.PrivateFix() }
