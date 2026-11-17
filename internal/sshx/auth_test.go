package sshx

import (
	"context"
	"errors"
	"strings"
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
		_, _, err := authMethods(context.Background(), &store.State{}, &store.Host{Name: "web1"}, 0, nil)
		oe := asOutErr(t, err)
		if oe.Code != "NO_AUTH" || oe.Exit != out.ExitConnect {
			t.Errorf("got %s exit %d, want NO_AUTH exit %d", oe.Code, oe.Exit, out.ExitConnect)
		}
	})
	t.Run("password ref unresolved", func(t *testing.T) {
		_, _, err := authMethods(context.Background(), &store.State{}, &store.Host{Name: "web1", PasswordRef: "env:KOMANDO_TEST_UNSET_PASSWORD"}, 0, nil)
		oe := asOutErr(t, err)
		if oe.Code != "SECRET_UNRESOLVED" || oe.Exit != out.ExitNotFound {
			t.Errorf("got %s exit %d, want SECRET_UNRESOLVED exit %d", oe.Code, oe.Exit, out.ExitNotFound)
		}
	})
}

// A stored password the server refused: AUTH_FAILED quotes the server's
// own question, and the password is not sent again.
func TestStoredPasswordRefusedKeepsTheQuestion(t *testing.T) {
	h := &store.Host{Name: "web1", Address: "10.0.0.1", PasswordRef: "env:X"}
	p := &passwordLogin{pw: "x", sent: true}
	ans, err := p.answer("", "", []string{"(u@10.0.0.1) Passwort für u:"}, []bool{false})
	var ua *unanswered
	if ans != nil || !errors.As(err, &ua) {
		t.Fatalf("%q %v", ans, err)
	}
	oe := ua.authFailed(newState(h), h)
	if oe.Code != "AUTH_FAILED" || !strings.Contains(oe.Message, "Passwort für u") || !strings.Contains(oe.Message, "stored password") {
		t.Errorf("%+v", oe)
	}
}
