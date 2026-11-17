package cli

import (
	"path/filepath"
	"testing"
)

// ~/.aws is a credential store as a whole, like ~/.kube and ~/.azure: the
// SSO token cache and the CLI's cached credentials are secrets too, not
// only the credentials file.
func TestAWSFolderIsACredentialStore(t *testing.T) {
	home := t.TempDir()
	accountHomeAt(t, home)
	setCallerEnv(t, "CLAUDECODE", "1")
	for _, p := range []string{
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".aws", "sso", "cache", "0123abcd.json"),
		filepath.Join(home, ".aws", "cli", "cache", "role.json"),
		filepath.Join(home, ".aws"),
	} {
		if localSecret(tcl, p) == "" {
			t.Errorf("%s is not kept from an agent", p)
		}
	}
	if !isCredentialStore(filepath.Join(home, ".aws"), home) {
		t.Error("~/.aws is not a credential store")
	}
}
