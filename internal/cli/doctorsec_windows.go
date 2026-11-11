//go:build windows

package cli

import (
	"os"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// platformChecks are doctor's notes about what Windows lacks: the
// Credential Manager for the vault key, and a desktop for the approval
// window. File modes say nothing on Windows (access lists decide), so the
// permissions check is a note too.
func platformChecks(add func(name string, ok, warn bool, detail string)) {
	add("permissions", false, true, "Windows keeps "+store.Home()+" private through its access list, which komando does not check yet; keep it inside your user profile")
	if _, err := vault.KeychainTool(); err != nil {
		add("keychain", false, true, "no Windows Credential Manager here ("+err.Error()+"): the vault key stays in store.key unless you set a passphrase with `komando secret passphrase`")
	}
	if os.Getenv("KOMANDO_NO_DIALOG") == "" && !interactiveDesktop() {
		add("approval_window", false, true, "komando cannot show its \"Allow once\" window here (no desktop session, a service or a remote shell): an AI agent's --yes, --allow-dangerous and --reveal stop, and a person runs those commands in their own terminal")
	}
}

// looseFiles: file modes do not show who may read a file on Windows.
func looseFiles() []string { return nil }
