package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// vpn add --ask-password works as host add's: a person types the VPN
// password once, hidden, and it lands in the vault as secret:NAME-pass.
// Agents and scripts are never asked.
func TestVpnAddAskPassword(t *testing.T) {
	invHome(t)
	noAgent(t)
	socks := func(name string, extra ...string) []string {
		return append([]string{"vpn", "add", name, "socks", "--proxy-address", "127.0.0.1:1080", "--user", "budi", "--ask-password"}, extra...)
	}
	// a script: no terminal
	if e := wantCode(t, "NEEDS_TERMINAL", socks("lab")...); !strings.Contains(e.Hint, "komando secret set lab-pass") {
		t.Errorf("script hint: %q", e.Hint)
	}
	// an agent
	asAgent(t, false, false)
	if e := wantCode(t, "NEEDS_PERSON", socks("lab")...); !strings.Contains(e.Hint, "never ask for a password in the chat") {
		t.Errorf("agent hint: %q", e.Hint)
	}
	noAgent(t)
	if _, e := invRun(t, "vpn", "show", "lab"); e == nil {
		t.Error("lab was added without its password")
	}

	// a person
	saved, savedInteractive := readPassword, tcl.terminal
	t.Cleanup(func() { readPassword, tcl.terminal = saved, savedInteractive })
	tcl.terminal = true
	asked := 0
	readPassword = func(_ *call, label string) (string, error) {
		asked++
		if !strings.HasPrefix(label, "Password for ") {
			t.Errorf("question: %q", label)
		}
		return "Typed-Vpn-1", nil
	}
	d := mustRun(t, socks("lab")...)
	if v, _ := d["vpn"].(map[string]any); v["key_ref"] != "secret:lab-pass" || asked != 1 {
		t.Errorf("vpn add --ask-password: %v (asked %d)", d, asked)
	}
	if strings.Contains(fmtAny(d["warnings"]), "lab-pass") {
		t.Errorf("warned about the password it stored: %v", d["warnings"])
	}
	if v, err := vault.Get("lab-pass"); err != nil || v != "Typed-Vpn-1" {
		t.Errorf("vault: %q %v", v, err)
	}
	// an l2tp login: the password is stored, so no person is needed at vpn up
	setSecret(t, "office-psk", "shared")
	d = mustRun(t, "vpn", "add", "office", "l2tp", "--server", "vpn.example.com", "--psk-ref", "secret:office-psk", "--user", "budi", "--ask-password")
	if v, _ := d["vpn"].(map[string]any); v["key_ref"] != "secret:office-pass" || v["mfa"] == true {
		t.Errorf("l2tp --ask-password: %v", d)
	}

	// refused together with --password-ref, and where no password is used
	asked = 0
	wantCode(t, "USAGE", socks("lab2", "--password-ref", "env:X")...)
	wantCode(t, "USAGE", "vpn", "add", "corp", "system", "--check", "10.0.0.1:443", "--ask-password")
	wantCode(t, "USAGE", "vpn", "add", "tail", "tailscale", "--ask-password")
	// a name that is taken is refused before anyone is asked
	wantCode(t, "VPN_EXISTS", socks("lab")...)
	if asked != 0 {
		t.Errorf("asked %d times for adds that were refused", asked)
	}

	// a failed add takes back the secret it made: here the name is taken
	// while the person types
	readPassword = func(*call, string) (string, error) {
		err := store.Update(store.Save(), func(s *store.State) error {
			s.Hosts["bad"] = &store.Host{Name: "bad", Address: "10.0.0.9"}
			return nil
		})
		return "Typed-Vpn-2", err
	}
	if _, e := invRun(t, socks("bad")...); e == nil {
		t.Fatal("a name taken meanwhile: the add must fail")
	}
	if _, err := vault.Get("bad-pass"); err == nil {
		t.Error("a failed add left its new secret in the vault")
	}

	// a dry run asks nothing and stores nothing
	readPassword = func(*call, string) (string, error) { asked++; return "x", nil }
	mustRun(t, socks("dry1", "--dry-run")...)
	if _, err := vault.Get("dry1-pass"); err == nil || asked != 0 {
		t.Errorf("dry run asked %d times or stored the secret", asked)
	}
}

// vpn add --overwrite --ask-password replaces the VPN's password only when
// the add goes through: a check that refuses it asks nothing, and an add
// refused after the person typed puts the old password back.
func TestVpnAddAskPasswordOverwriteRefused(t *testing.T) {
	invHome(t)
	noAgent(t)
	saved, savedInteractive := readPassword, tcl.terminal
	t.Cleanup(func() { readPassword, tcl.terminal = saved, savedInteractive })
	tcl.terminal = true
	asked := 0
	readPassword = func(*call, string) (string, error) { asked++; return "Old-Vpn-1", nil }
	socks := func(extra ...string) []string {
		return append([]string{"vpn", "add", "lab", "socks", "--proxy-address", "127.0.0.1:1080", "--user", "budi", "--ask-password"}, extra...)
	}
	mustRun(t, socks()...)
	if asked != 1 {
		t.Fatalf("asked %d times", asked)
	}
	keep := func(when string) {
		t.Helper()
		if v, err := vault.Get("lab-pass"); err != nil || v != "Old-Vpn-1" {
			t.Errorf("%s: lab-pass is %q (%v), want the old password", when, v, err)
		}
	}

	// refused by a check that runs before anyone is asked
	asked = 0
	wantCode(t, "USAGE", socks("--overwrite", "--legacy-crypto")...)
	if asked != 0 {
		t.Errorf("asked %d times for an add the checks refuse", asked)
	}
	keep("refused before asking")

	// refused after the person typed: the name became a server's meanwhile
	readPassword = func(*call, string) (string, error) {
		err := store.Update(store.Save(), func(s *store.State) error {
			delete(s.Vpns, "lab")
			s.Hosts["lab"] = &store.Host{Name: "lab", Address: "10.0.0.9"}
			return nil
		})
		return "New-Vpn-2", err
	}
	if _, e := invRun(t, socks("--overwrite")...); e == nil {
		t.Fatal("a name taken meanwhile: the add must fail")
	}
	keep("refused after asking")
}
