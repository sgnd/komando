package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// vpn serve runs for long, so the vault passphrase goes to it on stdin,
// after the SOCKS login and the typed password, never in its environment
// (`ps eww` shows that to every program of the user).
func TestVpnServeGetsPassphraseOnStdin(t *testing.T) {
	invHome(t)
	want := vault.Passphrase()
	t.Cleanup(func() { netx.SessionSecret = "" })
	s := &store.VpnSession{}
	c := serveCommand("/usr/local/bin/komando", "office", "typed-password", s)
	for _, e := range c.Env {
		if strings.HasPrefix(e, "KOMANDO_VAULT_PASS=") {
			t.Fatal("the passphrase is in vpn serve's environment")
		}
	}
	if !slices.Contains(c.Args, "--password-stdin") || c.Args[len(c.Args)-1] != vault.PassStdinFlag || s.SocksUser == "" || s.SocksPass == "" {
		t.Fatalf("args %q, session %+v", c.Args, s)
	}
	t.Setenv("KOMANDO_VAULT_PASS", "not-the-passphrase-sent")
	vault.Passphrase() // vpn serve starts without the real one
	user, pass, err := serveStdin(c.Stdin, true, true)
	if err != nil || user != s.SocksUser || pass != s.SocksPass || netx.SessionSecret != "typed-password" || vault.Passphrase() != want {
		t.Errorf("read %q %q %q, passphrase %q: %v", user, pass, netx.SessionSecret, vault.Passphrase(), err)
	}
	// no typed password: the second line is empty
	user, _, err = serveStdin(serveCommand("komando", "office", "", s).Stdin, true, true)
	if err != nil || user != s.SocksUser || netx.SessionSecret != "" || vault.Passphrase() != want {
		t.Errorf("without a typed password: %q %q %v", user, netx.SessionSecret, err)
	}
}
