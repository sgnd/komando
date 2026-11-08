package cli

import (
	"fmt"
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
