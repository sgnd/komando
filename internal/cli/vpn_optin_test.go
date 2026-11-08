package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// --legacy-crypto and --allow-pap weaken a VPN's login: turning one on
// needs a person's yes (an agent's --yes opens the window), turning it
// off does not, and only the kinds they apply to take them.
func TestVpnEditOptIns(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "add", "kantor", "l2tp", "--server", "vpn.kantor.id", "--psk-ref", "secret:kantor-psk", "--user", "budi", "--password-ref", "secret:kantor")
	mustRun(t, "vpn", "add", "asa", "ipsec", "--server", "asa.client.com", "--id", "staff", "--psk-ref", "secret:asa-group", "--user", "budi")
	vpn := func(name string) *store.Vpn {
		st, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		return st.Vpns[name]
	}
	if _, e := cliRun(t, "vpn", "edit", "kantor", "--legacy-crypto"); e == nil || e.Code != "SAFETY_SETTING" || !strings.Contains(e.Message, "3DES") {
		t.Fatalf("without --yes: %+v", e)
	}
	if v := vpn("kantor"); v.LegacyCrypto {
		t.Fatal("a refused change was saved")
	}
	d, e := cliRun(t, "--dry-run", "vpn", "edit", "kantor", "--allow-pap")
	if e != nil || !strings.Contains(fmt.Sprint(d["_meta"]), "SAFETY_SETTING") || vpn("kantor").AllowPAP {
		t.Errorf("--dry-run: %v %v", d, e)
	}
	mustRun(t, "vpn", "edit", "kantor", "--legacy-crypto", "--allow-pap", "--yes")
	if v := vpn("kantor"); !v.LegacyCrypto || !v.AllowPAP {
		t.Fatalf("with --yes: %+v", v)
	}
	mustRun(t, "vpn", "edit", "kantor", "--legacy-crypto=false", "--allow-pap=false") // safer: no yes needed
	if v := vpn("kantor"); v.LegacyCrypto || v.AllowPAP {
		t.Fatalf("turning them off: %+v", v)
	}
	if _, e := cliRun(t, "vpn", "edit", "asa", "--allow-pap", "--yes"); e == nil || !strings.Contains(e.Message, "--allow-pap is not used by ipsec") {
		t.Errorf("--allow-pap on ipsec: %+v", e)
	}
	windows := asAgent(t, false, true)
	if _, e := cliRun(t, "vpn", "edit", "asa", "--legacy-crypto", "--yes"); e == nil || e.Code != "SAFETY_SETTING" || *windows != 1 || vpn("asa").LegacyCrypto {
		t.Errorf("an agent whose person says no: %+v, %d windows", e, *windows)
	}
}

// vpn add takes --legacy-crypto and --allow-pap the way vpn edit does:
// turning one on needs a person's yes, and only l2tp (both) and ipsec
// (--legacy-crypto) take them.
func TestVpnAddOptIns(t *testing.T) {
	invHome(t)
	l2tp := []string{"vpn", "add", "old-office", "l2tp", "--server", "vpn.example.com", "--psk-ref", "secret:old-psk", "--user", "alice", "--password-ref", "secret:old"}
	saved := func() bool {
		st, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		return st.Vpns["old-office"] != nil
	}
	if _, e := cliRun(t, append(l2tp, "--legacy-crypto")...); e == nil || e.Code != "SAFETY_SETTING" || !strings.Contains(e.Message, "3DES") || saved() {
		t.Fatalf("without --yes: %+v", e)
	}
	d, e := cliRun(t, append([]string{"--dry-run"}, append(l2tp, "--allow-pap")...)...)
	if e != nil || !strings.Contains(fmt.Sprint(d["_meta"]), "SAFETY_SETTING") || saved() {
		t.Errorf("--dry-run: %v %v", d, e)
	}
	mustRun(t, append(l2tp, "--legacy-crypto", "--allow-pap", "--yes")...)
	st, _ := store.Load()
	if v := st.Vpns["old-office"]; v == nil || !v.LegacyCrypto || !v.AllowPAP {
		t.Fatalf("with --yes: %+v", v)
	}
	mustRun(t, append(l2tp, "--overwrite", "--legacy-crypto=false")...) // off: no yes needed
	for _, bad := range [][]string{
		{"vpn", "add", "asa", "ipsec", "--server", "asa.example.com", "--psk-ref", "secret:g", "--allow-pap", "--yes"},
		{"vpn", "add", "cloud", "ikev2", "--server", "vpn.example.com", "--user", "alice", "--legacy-crypto", "--yes"},
	} {
		if _, e := cliRun(t, bad...); e == nil || e.Code != "USAGE" || !strings.Contains(e.Message, "is not used by") {
			t.Errorf("%v: %+v", bad, e)
		}
	}
	windows := asAgent(t, false, true)
	if _, e := cliRun(t, "vpn", "add", "asa", "ipsec", "--server", "asa.example.com", "--psk-ref", "secret:g", "--legacy-crypto", "--yes"); e == nil || e.Code != "SAFETY_SETTING" || *windows != 1 {
		t.Errorf("an agent whose person says no: %+v, %d windows", e, *windows)
	}
}

// testProfile is an OpenVPN profile komando's own client reads; it does
// not say how to check the server's certificate, so adding it warns.
const testProfile = `client
dev tun
proto udp
remote vpn.example.com 1194
remote vpn2.example.com 443 tcp
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</ca>
`

// A VPN's login goes to its server on every connection. An AI agent that
// adds a VPN with a secret, env or file reference, or points one at a new
// server, needs a person's yes; the window names the references and the
// server. People and scripts go on as before.
func TestVpnSecretsNeedAPerson(t *testing.T) {
	secretHome(t)
	profile := filepath.Join(t.TempDir(), "office.ovpn")
	if err := os.WriteFile(profile, []byte(testProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	// a person or a script: no window, and the profile's warning is shown
	d := mustRun(t, "vpn", "add", "office", "openvpn", "--config", profile, "--check", "10.8.0.1:22", "--user", "alice", "--password-ref", "secret:db-pass")
	if w := fmt.Sprint(d["warnings"]); !strings.Contains(w, "does not say how to check the server's certificate") {
		t.Errorf("the profile's warning: %v", d)
	}
	wantCode(t, "RESERVED_SECRET", "vpn", "add", "x", "l2tp", "--server", "vpn.example.com", "--psk-ref", "secret:"+approvalSecret, "--user", "alice")

	texts := windowText(t, true)
	add := []string{"vpn", "add", "branch", "l2tp", "--server", "vpn.example.com", "--psk-ref", "secret:branch-psk", "--user", "alice", "--password-ref", "secret:db-pass"}
	for _, args := range [][]string{
		add,
		{"vpn", "add", "lab", "socks", "--address", "proxy.example.com:1080", "--user", "alice", "--password-ref", "env:GITHUB_TOKEN"},
		{"vpn", "add", "tailnet", "tailscale", "--password-ref", "file:/etc/ssl/private/site.key"},
		{"vpn", "edit", "office", "--password-ref", "secret:other"},
	} {
		if _, e := cliRun(t, args...); e == nil || e.Code != "SECRET_DESTINATION" {
			t.Fatalf("%v: want SECRET_DESTINATION, got %+v", args, e)
		}
	}
	if len(*texts) != 0 {
		t.Fatalf("no flag, no window: %q", *texts)
	}
	// no reference, or nothing new: nothing to ask
	mustRun(t, "vpn", "add", "lab", "socks", "--address", "127.0.0.1:1080")
	mustRun(t, "vpn", "edit", "office", "--notes", "head office", "--user", "bob")
	if len(*texts) != 0 {
		t.Fatalf("nothing new goes anywhere: %q", *texts)
	}

	if _, e := cliRun(t, append(add, "--yes")...); e != nil {
		t.Fatal(e)
	}
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "secret:branch-psk, secret:db-pass to vpn.example.com (vpn branch)") {
		t.Fatalf("window: %q", *texts)
	}
	if _, e := cliRun(t, "vpn", "edit", "branch", "--server", "vpn.evil.example"); e == nil || e.Code != "SECRET_DESTINATION" {
		t.Errorf("a new server: %+v", e)
	}
	if _, e := cliRun(t, "vpn", "add", "office", "openvpn", "--config", profile, "--check", "10.8.0.1:22", "--user", "alice", "--password-ref", "secret:db-pass", "--overwrite", "--yes"); e != nil {
		t.Fatal(e)
	}
	if w := (*texts)[len(*texts)-1]; !strings.Contains(w, "secret:db-pass to vpn.example.com:1194, vpn2.example.com:443 (vpn office)") {
		t.Errorf("an OpenVPN profile names its servers: %q", w)
	}

	// the person says no
	windowText(t, false)
	if _, e := cliRun(t, "vpn", "edit", "branch", "--server", "vpn.evil.example", "--yes"); e == nil || e.Code != "SECRET_DESTINATION" {
		t.Errorf("denied: %+v", e)
	}
	st, _ := store.Load()
	if st.Vpns["branch"].Server != "vpn.example.com" || st.Vpns["tailnet"] != nil {
		t.Error("a refused change was saved")
	}
}

// ovpnRemotes names every server of a profile, also those in <connection>
// blocks, and refuses what checkOVPN refuses.
func TestOvpnRemotes(t *testing.T) {
	got, err := ovpnRemotes("client\nremote b.example.com\n<connection>\nremote a.example.com 443 tcp\n</connection>\nremote b.example.com\n")
	if err != nil || got != "a.example.com:443, b.example.com" {
		t.Errorf("%q %v", got, err)
	}
	if _, err := ovpnRemotes("client\nup /tmp/x.sh\n"); err == nil {
		t.Error("a line OpenVPN must not get was taken")
	}
}
