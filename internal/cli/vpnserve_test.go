package cli

import (
	"slices"
	"strings"
	"testing"
	"time"

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

// TestSessionUseOpenConnIsNotIdle: a logged-in connection that stays open
// (a shell, logs --follow, a tunnel) keeps the session from going idle; it
// used to be cut at vpn_idle because only new logins counted.
func TestSessionUseOpenConnIsNotIdle(t *testing.T) {
	var u sessionUse
	u.touch()
	later := time.Now().Add(2 * time.Hour)
	if u.idleFor(later) < time.Hour {
		t.Fatal("an unused session is not idle")
	}
	loggedIn, done := u.conn()
	loggedIn()
	loggedIn() // once only
	if d := u.idleFor(later); d != 0 {
		t.Fatalf("idle %s while a logged-in connection is open", d)
	}
	done()
	if d := u.idleFor(time.Now()); d > time.Second {
		t.Fatalf("idle %s right after the connection closed", d)
	}
	// a client that never logged in counts for nothing
	_, done2 := u.conn()
	done2()
	if u.active.Load() != 0 {
		t.Fatalf("active = %d", u.active.Load())
	}
}
