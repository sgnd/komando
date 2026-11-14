package cli

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// vpnSecretFiles writes a WireGuard config with a preshared key and an
// OpenVPN profile, each in two versions (n = "1" or "2").
func vpnSecretFiles(t *testing.T) (wg, ovpn func(n string) string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	key := func(seed string) string { return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(seed, 16))) } // 32 bytes
	wg = func(n string) string {
		return write("wg"+n+".conf", "[Interface]\nPrivateKey = "+key("a"+n)+"\nAddress = 10.77.0.2/32\n\n[Peer]\nPublicKey = "+key("b0")+
			"\nPresharedKey = "+key("c"+n)+"\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.77.0.0/24\n")
	}
	ovpn = func(n string) string {
		return write("vpn"+n+".ovpn", "client\ndev tun\nproto udp\nremote vpn"+n+".example.com 1194\nremote-cert-tls server\n<ca>\nx\n</ca>\n<cert>\nx\n</cert>\n<key>\ny\n</key>\n")
	}
	return wg, ovpn
}

// `vpn add` keeps a VPN's keys in the vault secrets NAME-key and NAME-psk
// (WireGuard) or NAME-config (OpenVPN). It never replaces a secret of that
// name that is not the VPN's own: `vpn add prod ...` would overwrite a
// secret prod-key that a server uses, with a value the caller (an AI agent
// too) chose.
func TestVpnAddKeepsOtherSecrets(t *testing.T) {
	invHome(t)
	wg, ovpn := vpnSecretFiles(t)
	const theirs = "alice-key-passphrase"
	set := func(name string) {
		t.Helper()
		if err := vault.Set(store.Save(), name, theirs); err != nil {
			t.Fatal(err)
		}
	}
	kept := func(name string) {
		t.Helper()
		if v, err := vault.Get(name); err != nil || v != theirs {
			t.Errorf("secret %s was replaced: %q %v", name, v, err)
		}
	}
	noVpn := func(name string) {
		t.Helper()
		if st, _ := store.Load(); st.Vpns[name] != nil {
			t.Errorf("VPN %s was saved", name)
		}
	}
	if err := store.Update(store.Save(), func(s *store.State) error {
		s.Hosts["web"] = &store.Host{Name: "web", Address: "web.example.com", User: "alice", PasswordRef: "secret:prod-key"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// wireguard: NAME-key is taken, and a server uses it
	set("prod-key")
	for _, dry := range []bool{true, false} {
		args := []string{"vpn", "add", "prod", "wireguard", "--config", wg("1")}
		if dry {
			args = append([]string{"--dry-run"}, args...)
		}
		e := wantCode(t, "SECRET_EXISTS", args...)
		if !strings.Contains(e.Message, `"prod-key"`) || !strings.Contains(e.Message, "host web") || !strings.Contains(e.Hint, "pick another VPN name") ||
			!strings.Contains(e.Hint, "komando secret rename prod-key") {
			t.Errorf("dry run %v: %s (hint: %s)", dry, e.Message, e.Hint)
		}
	}
	kept("prod-key")
	noVpn("prod")
	if _, err := vault.Get("prod-psk"); err == nil {
		t.Error("the preshared key was stored although the add was refused")
	}

	// wireguard: only NAME-psk is taken; nothing is stored
	set("edge-psk")
	wantCode(t, "SECRET_EXISTS", "vpn", "add", "edge", "wireguard", "--config", wg("1"))
	kept("edge-psk")
	noVpn("edge")
	if _, err := vault.Get("edge-key"); err == nil {
		t.Error("the private key was stored although the add was refused")
	}

	// openvpn: NAME-config is taken, by nothing komando knows of
	set("lab-config")
	e := wantCode(t, "SECRET_EXISTS", "vpn", "add", "lab", "openvpn", "--config", ovpn("1"), "--check", "10.8.0.1:22")
	if !strings.Contains(e.Message, "OpenVPN profile") || strings.Contains(e.Message, "used by") {
		t.Errorf("openvpn: %s", e.Message)
	}
	kept("lab-config")
	noVpn("lab")

	// --overwrite with no VPN of that name to replace changes nothing
	wantCode(t, "SECRET_EXISTS", "vpn", "add", "lab", "openvpn", "--config", ovpn("1"), "--check", "10.8.0.1:22", "--overwrite")
	kept("lab-config")
	// nor does --overwrite of a VPN that only points at the secret: a SOCKS
	// VPN's password is not a key `vpn add` stored
	mustRun(t, "vpn", "add", "corp", "socks", "--proxy-address", "127.0.0.1:1080", "--user", "alice", "--password-ref", "secret:corp-key")
	set("corp-key")
	wantCode(t, "SECRET_EXISTS", "vpn", "add", "corp", "wireguard", "--config", wg("1"), "--overwrite")
	kept("corp-key")
	if st, _ := store.Load(); st.Vpns["corp"].Kind != "socks" {
		t.Error("the SOCKS VPN was replaced")
	}
}

// --overwrite replaces a WireGuard or OpenVPN VPN with a new config: its
// own secrets get the new keys. A secret something else uses as well, or
// the old name of a renamed VPN, stays.
func TestVpnAddOverwriteReusesOwnSecrets(t *testing.T) {
	invHome(t)
	wg, ovpn := vpnSecretFiles(t)
	get := func(name string) string {
		t.Helper()
		v, err := vault.Get(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return v
	}

	mustRun(t, "vpn", "add", "office", "wireguard", "--config", wg("1"))
	key1, psk1 := get("office-key"), get("office-psk")
	wantCode(t, "VPN_EXISTS", "vpn", "add", "office", "wireguard", "--config", wg("2"))
	mustRun(t, "--dry-run", "vpn", "add", "office", "wireguard", "--config", wg("2"), "--overwrite")
	if get("office-key") != key1 {
		t.Fatal("a dry run stored the key")
	}
	mustRun(t, "vpn", "add", "office", "wireguard", "--config", wg("2"), "--overwrite")
	if get("office-key") == key1 || get("office-psk") == psk1 {
		t.Error("--overwrite kept the old keys")
	}

	mustRun(t, "vpn", "add", "lab", "openvpn", "--config", ovpn("1"), "--check", "10.8.0.1:22")
	mustRun(t, "vpn", "add", "lab", "openvpn", "--config", ovpn("2"), "--check", "10.8.0.1:22", "--overwrite")
	if !strings.Contains(get("lab-config"), "vpn2.example.com") {
		t.Error("--overwrite kept the old profile")
	}

	// the VPN's own secret, but a server uses it too
	if err := store.Update(store.Save(), func(s *store.State) error {
		s.Hosts["web"] = &store.Host{Name: "web", Address: "web.example.com", User: "alice", PasswordRef: "secret:lab-config"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e := wantCode(t, "SECRET_EXISTS", "vpn", "add", "lab", "openvpn", "--config", ovpn("1"), "--check", "10.8.0.1:22", "--overwrite")
	if !strings.Contains(e.Message, "vpn lab") || !strings.Contains(e.Message, "host web") {
		t.Errorf("shared secret: %s", e.Message)
	}
	if !strings.Contains(get("lab-config"), "vpn2.example.com") {
		t.Error("the shared profile was replaced")
	}

	// `vpn mv` moves the secrets only it uses to the new name, so the old
	// name is free again; one a server uses too keeps its name
	mustRun(t, "vpn", "mv", "office", "office-east")
	key2 := get("office-east-key")
	if _, err := vault.Get("office-key"); err == nil {
		t.Error("office-key is still there after vpn mv")
	}
	if st, _ := store.Load(); st.Vpns["office-east"].KeyRef != "secret:office-east-key" || st.Vpns["office-east"].PSKRef != "secret:office-east-psk" {
		t.Errorf("refs after vpn mv: %+v", st.Vpns["office-east"])
	}
	mustRun(t, "vpn", "add", "office", "wireguard", "--config", wg("1"))
	if get("office-east-key") != key2 {
		t.Error("the renamed VPN's key was replaced")
	}
	d := mustRun(t, "vpn", "mv", "lab", "lab-2")
	if w := d["warnings"].([]any); len(w) != 1 || !strings.Contains(w[0].(string), "lab-config keeps its name") {
		t.Errorf("shared secret on vpn mv: %v", d)
	}
	if st, _ := store.Load(); st.Vpns["lab-2"].ConfigRef != "secret:lab-config" {
		t.Error("a shared secret moved")
	}
}

// After `vpn rm`, adding the VPN again from the same file reuses the key
// it left behind: the value is the same, so nothing that uses it changes.
// A different file still stops.
func TestVpnReAddAfterRm(t *testing.T) {
	invHome(t)
	wg, _ := vpnSecretFiles(t)
	mustRun(t, "vpn", "add", "wg2", "wireguard", "--config", wg("1"))
	mustRun(t, "vpn", "rm", "wg2")
	wantCode(t, "SECRET_EXISTS", "vpn", "add", "wg2", "wireguard", "--config", wg("2"))
	d := mustRun(t, "vpn", "add", "wg2", "wireguard", "--config", wg("1"), "--check", "10.77.0.1:22")
	if d["warnings"] != nil {
		t.Errorf("warnings for the keys this add stored: %v", d["warnings"])
	}
}
