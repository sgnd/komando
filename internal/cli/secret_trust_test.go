package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// putVpn stores a VPN as a person's `vpn add` would have, and the vault
// secrets it uses.
func putVpn(t *testing.T, v *store.Vpn, secrets map[string]string) {
	t.Helper()
	for n, val := range secrets {
		if err := vault.Set(store.Save(), n, val); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Update(store.Save(), func(s *store.State) error { s.Vpns[v.Name] = v; return nil }); err != nil {
		t.Fatal(err)
	}
}

func secretIs(t *testing.T, name, want string) {
	t.Helper()
	if got, err := vault.Get(name); err != nil || got != want {
		t.Errorf("secret %s = %q, %v; want %q", name, got, err, want)
	}
}

// A protected VPN's key, preshared key or profile in the vault is replaced
// only with a person's yes, like a protected server's password: through
// secret set, secret cp --overwrite and secret rename --overwrite.
func TestProtectedVpnSecretNeedsYes(t *testing.T) {
	secretHome(t)
	putVpn(t, &store.Vpn{Name: "office", Kind: "wireguard", KeyRef: "secret:office-key", PSKRef: "secret:office-psk", Protected: true,
		Config: "[Interface]\nAddress = 10.66.0.2/32\n"}, map[string]string{"office-key": "key-1", "office-psk": "psk-1", "other": "agent-value"})
	texts := windowText(t, true)
	t.Setenv("V", "agent-value")
	wantCode(t, "PROTECTED_TARGET", "secret", "set", "office-key", "--from-env", "V")
	wantCode(t, "PROTECTED_TARGET", "secret", "cp", "other", "office-psk", "--overwrite")
	wantCode(t, "PROTECTED_TARGET", "secret", "rename", "other", "office-key", "--overwrite")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	secretIs(t, "office-key", "key-1")
	secretIs(t, "office-psk", "psk-1")
	if u := protectedUsers(mustState(t), []string{"vpn office", "vpn nosuch", "host nosuch"}); len(u) != 1 || u[0] != "vpn office" {
		t.Errorf("protectedUsers: %v", u)
	}
}

const ovpnOld = "client\nremote vpn.corp.example 1194\n<ca>\nOLD\n</ca>\n"
const ovpnEvil = "client\nremote evil.example 443\n<ca>\nEVIL\n</ca>\n"

// An OpenVPN VPN's profile in the vault says where its login goes and
// which CA is trusted. An AI agent that replaces that secret (secret set,
// cp --overwrite, rename --overwrite) needs a person's yes, as vpn edit
// does for the same change; the window names the new servers.
func TestOvpnProfileSecretNeedsAPerson(t *testing.T) {
	secretHome(t)
	putVpn(t, &store.Vpn{Name: "corp", Kind: "openvpn", ConfigRef: "secret:corp-config", KeyRef: "secret:corp-pass", User: "ana"},
		map[string]string{"corp-config": ovpnOld, "corp-pass": "pw", "evil": ovpnEvil})
	texts := windowText(t, true)
	t.Setenv("V", ovpnEvil)
	wantCode(t, "SECRET_DESTINATION", "secret", "set", "corp-config", "--from-env", "V")
	wantCode(t, "SECRET_DESTINATION", "secret", "cp", "evil", "corp-config", "--overwrite")
	wantCode(t, "SECRET_DESTINATION", "secret", "rename", "evil", "corp-config", "--overwrite")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	secretIs(t, "corp-config", ovpnOld)
	secretIs(t, "evil", ovpnEvil)

	// the same value again changes nothing: not asked
	t.Setenv("V", ovpnOld)
	mustRun(t, "secret", "set", "corp-config", "--from-env", "V")
	// another secret is not asked about
	mustRun(t, "secret", "set", "evil", "--from-env", "V")
	if len(*texts) != 0 {
		t.Errorf("nothing changes where a login goes: %q", *texts)
	}

	t.Setenv("V", ovpnEvil)
	mustRun(t, "secret", "set", "corp-config", "--from-env", "V", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "secret:corp-pass to evil.example:443") || !strings.Contains((*texts)[0], "vpn corp") {
		t.Errorf("window: %q", *texts)
	}
	secretIs(t, "corp-config", ovpnEvil)

	// a person or a script is not asked
	noAgent(t)
	t.Setenv("V", ovpnOld)
	mustRun(t, "secret", "set", "corp-config", "--from-env", "V")
}

// The CA certificate a WinRM server or a conn is checked against lives in
// a vault secret (?ca=secret:NAME). An AI agent that replaces it, or makes
// one that was missing, needs a person's yes: another CA lets another
// server pass as that one and get its password.
func TestCASecretNeedsAPerson(t *testing.T) {
	secretHome(t)
	for n, v := range map[string]string{"win-ca": "PEM-1", "db-ca": "PEM-2", "mine": "PEM-AGENT", "win-pass": "pw"} {
		if err := vault.Set(store.Save(), n, v); err != nil {
			t.Fatal(err)
		}
	}
	mustRun(t, "host", "add", "win1", "winrm://Administrator@10.0.0.9?ca=secret:win-ca", "--password-ref", "secret:win-pass")
	mustRun(t, "host", "add", "win2", "winrm://Administrator@10.0.0.10?ca=secret:later-ca")
	mustRun(t, "conn", "add", "shop", "postgres://app@10.0.0.5/app?sslmode=verify-full&ca=secret:db-ca")
	texts := windowText(t, true)
	t.Setenv("V", "PEM-AGENT")
	wantCode(t, "SAFETY_SETTING", "secret", "set", "win-ca", "--from-env", "V")
	wantCode(t, "SAFETY_SETTING", "secret", "cp", "mine", "win-ca", "--overwrite")
	wantCode(t, "SAFETY_SETTING", "secret", "rename", "mine", "db-ca", "--overwrite")
	wantCode(t, "SAFETY_SETTING", "secret", "set", "later-ca", "--from-env", "V")
	wantCode(t, "SAFETY_SETTING", "secret", "cp", "mine", "later-ca")
	wantCode(t, "SAFETY_SETTING", "secret", "rename", "mine", "later-ca")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	secretIs(t, "win-ca", "PEM-1")
	secretIs(t, "db-ca", "PEM-2")
	if _, err := vault.Get("later-ca"); err == nil {
		t.Error("later-ca was made")
	}
	// a password is not a CA: replaced as before
	mustRun(t, "secret", "set", "win-pass", "--from-env", "V")
	if len(*texts) != 0 {
		t.Errorf("a password asks nothing: %q", *texts)
	}
	mustRun(t, "secret", "set", "win-ca", "--from-env", "V", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "server win1") || !strings.Contains((*texts)[0], "CA certificate") {
		t.Errorf("window: %q", *texts)
	}
	secretIs(t, "win-ca", "PEM-AGENT")
}

// An AI agent that points a WinRM server at another CA certificate
// (host edit ...?ca=secret:OTHER) needs a person's yes, like tls=skip-verify.
func TestWinRMOtherCANeedsAPerson(t *testing.T) {
	secretHome(t)
	for n, v := range map[string]string{"win-ca": "PEM-1", "mine": "PEM-AGENT"} {
		if err := vault.Set(store.Save(), n, v); err != nil {
			t.Fatal(err)
		}
	}
	mustRun(t, "host", "add", "win1", "winrm://Administrator@10.0.0.9?ca=secret:win-ca")
	mustRun(t, "host", "add", "win2", "winrm://Administrator@10.0.0.10")
	texts := windowText(t, true)
	wantCode(t, "SAFETY_SETTING", "host", "edit", "win1", "--address", "winrm://Administrator@10.0.0.9?ca=secret:mine")
	wantCode(t, "SAFETY_SETTING", "host", "edit", "win2", "--address", "winrm://Administrator@10.0.0.10?ca=secret:mine")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	if h := mustState(t).Hosts["win1"]; h.WinRMOpts.CA != "secret:win-ca" {
		t.Errorf("win1 trusts %s", h.WinRMOpts.CA)
	}
	// a new server with a CA of its own, and dropping the extra CA, ask nothing
	mustRun(t, "host", "add", "win3", "winrm://Administrator@10.0.0.11?ca=secret:win-ca")
	mustRun(t, "host", "edit", "win1", "--address", "winrm://Administrator@10.0.0.9")
	if len(*texts) != 0 {
		t.Errorf("nothing weaker: %q", *texts)
	}
	mustRun(t, "host", "edit", "win2", "--address", "winrm://Administrator@10.0.0.10?ca=secret:mine", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "server win2") || !strings.Contains((*texts)[0], "CA certificate") {
		t.Errorf("window: %q", *texts)
	}
}
