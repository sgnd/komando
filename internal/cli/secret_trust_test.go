package cli

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/inventory"
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
// secret set and secret rename --overwrite.
func TestProtectedVpnSecretNeedsYes(t *testing.T) {
	secretHome(t)
	putVpn(t, &store.Vpn{Name: "office", Kind: "wireguard", KeyRef: "credential:office-key", PSKRef: "credential:office-psk", Protected: true,
		Config: "[Interface]\nAddress = 10.66.0.2/32\n"}, map[string]string{"office-key": "key-1", "office-psk": "psk-1", "other": "agent-value"})
	texts := windowText(t, true)
	t.Setenv("V", "agent-value")
	wantCode(t, "PROTECTED_TARGET", "credential", "password", "add", "office-key", "--from-env", "V")
	wantCode(t, "PROTECTED_TARGET", "credential", "password", "rename", "other", "office-psk", "--overwrite")
	wantCode(t, "PROTECTED_TARGET", "credential", "password", "rename", "other", "office-key", "--overwrite")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	secretIs(t, "office-key", "key-1")
	secretIs(t, "office-psk", "psk-1")
	if u := inventory.ProtectedUsers(mustState(t), []string{"vpn office", "vpn nosuch", "host nosuch"}); len(u) != 1 || u[0] != "vpn office" {
		t.Errorf("inventory.ProtectedUsers: %v", u)
	}
}

const ovpnOld = "client\nremote vpn.corp.example 1194\n<ca>\nOLD\n</ca>\n"
const ovpnEvil = "client\nremote evil.example 443\n<ca>\nEVIL\n</ca>\n"

// An OpenVPN VPN's profile in the vault says where its login goes and
// which CA is trusted. An AI agent that replaces that secret (secret set,
// rename --overwrite) needs a person's yes, as vpn edit
// does for the same change; the window names the new servers.
func TestOvpnProfileSecretNeedsAPerson(t *testing.T) {
	secretHome(t)
	putVpn(t, &store.Vpn{Name: "corp", Kind: "openvpn", ConfigRef: "credential:corp-config", KeyRef: "credential:corp-pass", User: "ana"},
		map[string]string{"corp-config": ovpnOld, "corp-pass": "pw", "evil": ovpnEvil})
	texts := windowText(t, true)
	t.Setenv("V", ovpnEvil)
	wantCode(t, "SECRET_DESTINATION", "credential", "password", "add", "corp-config", "--from-env", "V")
	wantCode(t, "SECRET_DESTINATION", "credential", "password", "rename", "evil", "corp-config", "--overwrite")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	secretIs(t, "corp-config", ovpnOld)
	secretIs(t, "evil", ovpnEvil)

	// the same value again changes nothing: not asked
	t.Setenv("V", ovpnOld)
	mustRun(t, "credential", "password", "add", "corp-config", "--from-env", "V")
	// another secret is not asked about
	mustRun(t, "credential", "password", "add", "evil", "--from-env", "V")
	if len(*texts) != 0 {
		t.Errorf("nothing changes where a login goes: %q", *texts)
	}

	t.Setenv("V", ovpnEvil)
	mustRun(t, "credential", "password", "add", "corp-config", "--from-env", "V", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "credential:corp-pass to evil.example:443") || !strings.Contains((*texts)[0], "vpn corp") {
		t.Errorf("window: %q", *texts)
	}
	secretIs(t, "corp-config", ovpnEvil)

	// a person or a script is not asked
	noAgent(t)
	t.Setenv("V", ovpnOld)
	mustRun(t, "credential", "password", "add", "corp-config", "--from-env", "V")
}

// The CA certificate a WinRM server or a conn is checked against lives in
// a vault secret (?ca=credential:NAME). An AI agent that replaces it, or makes
// one that was missing, needs a person's yes: another CA lets another
// server pass as that one and get its password.
func TestCASecretNeedsAPerson(t *testing.T) {
	secretHome(t)
	for n, v := range map[string]string{"win-ca": "PEM-1", "db-ca": "PEM-2", "mine": "PEM-AGENT", "win-pass": "pw"} {
		if err := vault.Set(store.Save(), n, v); err != nil {
			t.Fatal(err)
		}
	}
	mustRun(t, "host", "winrm", "add", "win1", "winrm://Administrator@10.0.0.9?ca=credential:win-ca", "--credential", "win-pass")
	mustRun(t, "host", "winrm", "add", "win2", "winrm://Administrator@10.0.0.10?ca=credential:later-ca")
	mustRun(t, "conn", "add", "shop", "postgres://app@10.0.0.5/app?sslmode=verify-full&ca=credential:db-ca")
	texts := windowText(t, true)
	t.Setenv("V", "PEM-AGENT")
	wantCode(t, "SAFETY_SETTING", "credential", "password", "add", "win-ca", "--from-env", "V")
	wantCode(t, "SAFETY_SETTING", "credential", "password", "rename", "mine", "win-ca", "--overwrite")
	wantCode(t, "SAFETY_SETTING", "credential", "password", "rename", "mine", "db-ca", "--overwrite")
	wantCode(t, "SAFETY_SETTING", "credential", "password", "add", "later-ca", "--from-env", "V")
	wantCode(t, "SAFETY_SETTING", "credential", "password", "rename", "mine", "later-ca")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	secretIs(t, "win-ca", "PEM-1")
	secretIs(t, "db-ca", "PEM-2")
	if _, err := vault.Get("later-ca"); err == nil {
		t.Error("later-ca was made")
	}
	// a password is not a CA: replaced as before
	mustRun(t, "credential", "password", "add", "win-pass", "--from-env", "V")
	if len(*texts) != 0 {
		t.Errorf("a password asks nothing: %q", *texts)
	}
	mustRun(t, "credential", "password", "add", "win-ca", "--from-env", "V", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "server win1") || !strings.Contains((*texts)[0], "CA certificate") {
		t.Errorf("window: %q", *texts)
	}
	secretIs(t, "win-ca", "PEM-AGENT")
}

// An AI agent that points a WinRM server at another CA certificate
// (host edit ...?ca=credential:OTHER) needs a person's yes, like tls=skip-verify.
func TestWinRMOtherCANeedsAPerson(t *testing.T) {
	secretHome(t)
	for n, v := range map[string]string{"win-ca": "PEM-1", "mine": "PEM-AGENT"} {
		if err := vault.Set(store.Save(), n, v); err != nil {
			t.Fatal(err)
		}
	}
	mustRun(t, "host", "winrm", "add", "win1", "winrm://Administrator@10.0.0.9?ca=credential:win-ca")
	mustRun(t, "host", "winrm", "add", "win2", "winrm://Administrator@10.0.0.10")
	texts := windowText(t, true)
	wantCode(t, "SAFETY_SETTING", "host", "winrm", "edit", "win1", "--address", "winrm://Administrator@10.0.0.9?ca=credential:mine")
	wantCode(t, "SAFETY_SETTING", "host", "winrm", "edit", "win2", "--address", "winrm://Administrator@10.0.0.10?ca=credential:mine")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	if h := mustState(t).Hosts["win1"]; h.WinRMOpts.CA != "credential:win-ca" {
		t.Errorf("win1 trusts %s", h.WinRMOpts.CA)
	}
	// a new server with a CA of its own, and dropping the extra CA, ask nothing
	mustRun(t, "host", "winrm", "add", "win3", "winrm://Administrator@10.0.0.11?ca=credential:win-ca")
	mustRun(t, "host", "winrm", "edit", "win1", "--address", "winrm://Administrator@10.0.0.9")
	if len(*texts) != 0 {
		t.Errorf("nothing weaker: %q", *texts)
	}
	mustRun(t, "host", "winrm", "edit", "win2", "--address", "winrm://Administrator@10.0.0.10?ca=credential:mine", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "server win2") || !strings.Contains((*texts)[0], "CA certificate") {
		t.Errorf("window: %q", *texts)
	}
}

// Moving a jump server moves the way to everything reached through it: an
// AI agent that gives the hop a new address or port needs a person's yes
// when a conn or server behind it sends a vault password that way.
func TestMovedHopNeedsAPerson(t *testing.T) {
	secretHome(t)
	mustRun(t, "host", "ssh", "add", "jump", "u@10.0.0.3")
	mustRun(t, "host", "ssh", "add", "edge", "u@10.0.0.4")
	mustRun(t, "host", "ssh", "add", "inner", "u@10.0.1.1", "--via", "edge,jump", "--sudo-credential", "db-pass")
	mustRun(t, "conn", "add", "shop", "postgres://app@10.0.0.5/app", "--password-ref", "credential:db-pass", "--via", "jump")
	mustRun(t, "host", "ssh", "add", "lone", "u@10.0.0.8")
	texts := windowText(t, true)
	wantCode(t, "SECRET_DESTINATION", "host", "ssh", "edit", "jump", "--address", "10.6.6.6")
	wantCode(t, "SECRET_DESTINATION", "host", "ssh", "edit", "jump", "--port", "2222")
	wantCode(t, "SECRET_DESTINATION", "host", "ssh", "add", "jump", "u@10.6.6.6", "--overwrite")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	if h := mustState(t).Hosts["jump"]; h.Address != "10.0.0.3" || h.EffectivePort() != 22 {
		t.Errorf("jump moved: %+v", h)
	}
	// nothing behind it, or nothing about the way there: not asked
	mustRun(t, "host", "ssh", "edit", "lone", "--address", "10.0.0.88")
	mustRun(t, "host", "ssh", "edit", "jump", "--add-tag", "hop")
	if len(*texts) != 0 {
		t.Errorf("nothing re-routed: %q", *texts)
	}
	mustRun(t, "host", "ssh", "edit", "jump", "--address", "10.6.6.6", "--yes")
	if len(*texts) != 1 {
		t.Fatalf("one window: %q", *texts)
	}
	for _, want := range []string{"credential:db-pass", "conn shop", "server inner", "10.6.6.6:22"} {
		if !strings.Contains((*texts)[0], want) {
			t.Errorf("window lacks %q: %q", want, (*texts)[0])
		}
	}
}

// An import that replaces a vault secret (import env --overwrite stores a
// conn's password as CONN-pass) gets the same checks as secret set: a
// secret a protected entry uses, an OpenVPN profile, a CA certificate.
func TestImportReplacingATrustSecretNeedsAPerson(t *testing.T) {
	secretHome(t)
	putVpn(t, &store.Vpn{Name: "corp", Kind: "openvpn", ConfigRef: "credential:x-pass", KeyRef: "credential:corp-pass", User: "ana"},
		map[string]string{"x-pass": ovpnOld, "corp-pass": "pw"})
	putVpn(t, &store.Vpn{Name: "office", Kind: "wireguard", KeyRef: "credential:y-pass", Protected: true, Config: "[Interface]\n"},
		map[string]string{"y-pass": "key-1"})
	env := filepath.Join(t.TempDir(), "app.env")
	if err := os.WriteFile(env, []byte("X_URL=postgres://app:"+url.QueryEscape(ovpnEvil)+"@10.9.9.9:5432/app\nY_URL=postgres://app:agentkey@10.9.9.8:5432/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	only := filepath.Join(t.TempDir(), "x.env") // the profile alone
	if err := os.WriteFile(only, []byte("X_URL=postgres://app:"+url.QueryEscape(ovpnEvil)+"@10.9.9.9:5432/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	texts := windowText(t, true)
	wantCode(t, "PROTECTED_TARGET", "import", "env", env, "--overwrite") // the protected VPN's key stops it first
	e := wantCode(t, "SECRET_DESTINATION", "import", "env", only, "--overwrite")
	if strings.Contains(e.Message, "vpn.corp.example") {
		t.Errorf("the message shows where the old profile pointed, which the agent cannot read: %s", e.Message)
	}
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	secretIs(t, "x-pass", ovpnOld)
	secretIs(t, "y-pass", "key-1")
	// a dry run says so too, and changes nothing
	d := mustRun(t, "import", "env", only, "--overwrite", "--dry-run")
	if wb, _ := d["_meta"].(map[string]any)["would_be_blocked"].(map[string]any); wb == nil {
		t.Errorf("dry run: %v", d)
	}
	secretIs(t, "x-pass", ovpnOld)
}

// A profile renamed over another secret is named by that secret, never by
// the servers in it (the agent cannot read it); and a VPN whose login a
// person types at `vpn up` gets a new profile only from a person.
func TestOvpnProfileCopyAndTypedLogin(t *testing.T) {
	secretHome(t)
	putVpn(t, &store.Vpn{Name: "corp", Kind: "openvpn", ConfigRef: "credential:corp-config", KeyRef: "credential:corp-pass", User: "ana"},
		map[string]string{"corp-config": ovpnOld, "corp-pass": "pw", "hidden-profile": "client\nremote hidden-host.internal 7777\n"})
	putVpn(t, &store.Vpn{Name: "typed", Kind: "openvpn", ConfigRef: "credential:typed-config"}, map[string]string{"typed-config": ovpnOld})
	windowText(t, true)
	for _, args := range [][]string{{"credential", "password", "rename", "hidden-profile", "corp-config", "--overwrite", "--dry-run"}, {"credential", "password", "rename", "hidden-profile", "corp-config", "--overwrite"}} {
		_, text := runMain(t, args...)
		if strings.Contains(text, "hidden-host") || !strings.Contains(text, "secret hidden-profile") {
			t.Errorf("%v: %s", args, text)
		}
	}
	t.Setenv("V", ovpnEvil)
	wantCode(t, "NEEDS_PERSON", "credential", "password", "add", "typed-config", "--from-env", "V", "--yes")
	secretIs(t, "typed-config", ovpnOld)
}

// What lies behind a moved hop is asked about also when the same edit
// names it, and also when it is reached through a second hop.
func TestMovedHopReachesEverythingBehindIt(t *testing.T) {
	secretHome(t)
	mustRun(t, "host", "ssh", "add", "jump", "u@10.0.0.3", "--port", "2222")
	mustRun(t, "host", "ssh", "add", "inner", "u@10.0.1.1", "--via", "jump", "--sudo-credential", "db-pass")
	mustRun(t, "host", "ssh", "add", "mid", "u@10.0.1.2", "--via", "jump")
	mustRun(t, "conn", "add", "shop", "postgres://app@10.0.0.5/app", "--password-ref", "credential:db-pass", "--via", "mid")
	texts := windowText(t, true)
	wantCode(t, "SECRET_DESTINATION", "host", "ssh", "edit", "jump,inner", "--port", "22")
	if e := wantCode(t, "SECRET_DESTINATION", "host", "ssh", "edit", "jump", "--address", "10.6.6.6"); !strings.Contains(e.Message, "conn shop") {
		t.Errorf("the conn behind the second hop is named: %s", e.Message)
	}
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
}

// Every place a vault secret is named counts as a use, and a rename
// changes each of them: a server's password, sudo, WinRM CA and
// environment, a conn's password and URL option, a key's passphrase and a
// VPN's key, preshared key and config. A protected one is named as such.
func TestSecretRefsEveryKind(t *testing.T) {
	ref := "credential:s"
	st := &store.State{
		Hosts: map[string]*store.Host{
			"h1": {Name: "h1", PasswordRef: ref},
			"h2": {Name: "h2", SudoRef: ref, Protected: true},
			"h3": {Name: "h3", WinRMOpts: &store.WinRMOpts{CA: ref}},
			"h4": {Name: "h4", Env: map[string]string{"A": "x", "B": ref}},
			"h5": {Name: "h5", PasswordRef: "credential:other"},
		},
		Conns: map[string]*store.Conn{
			"c1": {Name: "c1", PasswordRef: ref},
			"c2": {Name: "c2", URL: "registry://u@h?tls=&ca=credential:s#f"},
		},
		Keys: map[string]*store.Key{"k1": {Name: "k1", PassphraseRef: ref}},
		Vpns: map[string]*store.Vpn{
			"v1": {Name: "v1", KeyRef: ref},
			"v2": {Name: "v2", PSKRef: ref},
			"v3": {Name: "v3", ConfigRef: ref},
		},
	}
	want := "conn c1,conn c2,host h1,host h2,host h3,host h4,key k1,vpn v1,vpn v2,vpn v3"
	if got := strings.Join(inventory.SecretUsers(st, "s"), ","); got != want {
		t.Fatalf("secretUsers: %s, want %s", got, want)
	}
	if got := strings.Join(inventory.ProtectedUsers(st, inventory.SecretUsers(st, "s")), ","); got != "host h2" {
		t.Errorf("protectedUsers: %s", got)
	}
	if got := strings.Join(inventory.RenameSecretRefs(st, "s", "t"), ","); got != want {
		t.Errorf("renameSecretRefs: %s, want %s", got, want)
	}
	if got := strings.Join(inventory.SecretUsers(st, "t"), ","); got != want {
		t.Errorf("after the rename: %s, want %s", got, want)
	}
	if len(inventory.SecretUsers(st, "s")) != 0 || st.Hosts["h4"].Env["B"] != "credential:t" || st.Hosts["h4"].Env["A"] != "x" ||
		st.Conns["c2"].URL != "registry://u@h?tls=&ca=credential:t#f" || st.Hosts["h5"].PasswordRef != "credential:other" {
		t.Errorf("rename left: %+v %q", st.Hosts["h4"].Env, st.Conns["c2"].URL)
	}
	if got := inventory.URLSecretRefs("registry://u@h?tls=&ca=credential:s&cert=credential:c"); len(got) != 2 {
		t.Errorf("urlSecretRefs: %+v, want two", got)
	}
}
