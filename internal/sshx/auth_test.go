package sshx

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// A server with no way to log in is a login problem (exit 4, like
// AUTH_FAILED), and a password reference that cannot be read is a missing
// secret (exit 3, like everywhere else SECRET_UNRESOLVED is returned).
func TestAuthMethodsErrorExitCodes(t *testing.T) {
	fakeHome := t.TempDir() // no ~/.ssh/id_* keys
	t.Setenv("HOME", fakeHome)
	t.Setenv("USERPROFILE", fakeHome) // os.UserHomeDir reads USERPROFILE on Windows
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Run("no auth", func(t *testing.T) {
		_, _, err := authMethods(&store.State{}, &store.Host{Name: "web1"}, 0)
		oe := asOutErr(t, err)
		if oe.Code != "NO_AUTH" || oe.Exit != out.ExitConnect {
			t.Errorf("got %s exit %d, want NO_AUTH exit %d", oe.Code, oe.Exit, out.ExitConnect)
		}
	})
	t.Run("password ref unresolved", func(t *testing.T) {
		_, _, err := authMethods(&store.State{}, &store.Host{Name: "web1", PasswordRef: "env:KOMANDO_TEST_UNSET_PASSWORD"}, 0)
		oe := asOutErr(t, err)
		if oe.Code != "SECRET_UNRESOLVED" || oe.Exit != out.ExitNotFound {
			t.Errorf("got %s exit %d, want SECRET_UNRESOLVED exit %d", oe.Code, oe.Exit, out.ExitNotFound)
		}
	})
}
