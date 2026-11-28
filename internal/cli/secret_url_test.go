package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// A secret that only a conn URL option names (a registry's
// ?ca=credential:NAME) counts as used everywhere: secret list, rm, mv, export
// and doctor.
func TestSecretRefInConnURL(t *testing.T) {
	invHome(t)
	setSecret(t, "reg-ca", "-----BEGIN CERTIFICATE-----")
	const url = "registry://deploy@registry.lan?ca=credential:reg-ca"
	if err := store.Update(store.Save(), func(s *store.State) error {
		s.Conns = map[string]*store.Conn{"reg": {Name: "reg", Kind: "registry", URL: url, Protected: true}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	d := mustRun(t, "credential", "list")
	row := d["secrets"].([]any)[0].(map[string]any)
	if u := row["used_by"].([]any); len(u) != 1 || u[0] != "conn reg" {
		t.Errorf("secret list used_by: %v", row)
	}
	wantCode(t, "SECRET_IN_USE", "credential", "password", "remove", "reg-ca")
	wantCode(t, "SECRET_IN_USE", "credential", "password", "remove", "reg-ca", "--dry-run")

	exp := mustRun(t, "export")
	if n := exp["secrets_needed"].([]any); len(n) != 1 || n[0] != "reg-ca" {
		t.Errorf("export secrets_needed: %v", n)
	}

	d = mustRun(t, "credential", "password", "rename", "reg-ca", "registry-ca", "--dry-run")
	if u := d["would_update"].([]any); len(u) != 1 || u[0] != "conn reg" {
		t.Errorf("mv dry run: %v", d)
	}
	st, _ := loadState()
	if st.Conns["reg"].URL != url {
		t.Fatalf("the dry run changed the URL: %s", st.Conns["reg"].URL)
	}

	d = mustRun(t, "credential", "password", "rename", "reg-ca", "registry-ca")
	if u := d["updated"].([]any); len(u) != 1 || u[0] != "conn reg" {
		t.Errorf("mv: %v", d)
	}
	st, _ = loadState()
	if got := st.Conns["reg"].URL; got != "registry://deploy@registry.lan?ca=credential:registry-ca" {
		t.Errorf("URL after mv: %s", got)
	}

	// doctor: quiet while the secret is there, a warning once it is gone
	for _, c := range inventoryChecks(tcl, st) {
		if c.Name == "conn:reg" {
			t.Errorf("doctor: %+v", c)
		}
	}
	if err := store.Update(store.Save(), func(s *store.State) error {
		s.Conns["reg"].URL = "registry://deploy@registry.lan?ca=credential:nope"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, _ = loadState()
	found := false
	for _, c := range inventoryChecks(tcl, st) {
		if c.Name == "conn:reg" && c.Warning && strings.Contains(c.Detail, "ca names a secret that is not in the vault") && !strings.Contains(c.Detail, "nope") {
			found = true
		}
	}
	if !found {
		t.Errorf("doctor does not warn about the missing CA secret: %+v", inventoryChecks(tcl, st))
	}
}

func TestViaTimeoutNamesThePath(t *testing.T) {
	mk := func() error {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --connect-timeout", "connecting to %s timed out", "10.0.0.5:5432")
	}
	if e := toErr(viaTimeout(&store.Conn{Via: "jump, office-vpn"}, mk())); e.Message != "connecting to 10.0.0.5:5432 via jump → office-vpn timed out" {
		t.Errorf("via: %s", e.Message)
	}
	if e := toErr(viaTimeout(&store.Conn{}, mk())); e.Message != "connecting to 10.0.0.5:5432 timed out" {
		t.Errorf("no via: %s", e.Message)
	}
	other := out.Errf(out.ExitConnect, "DB_AUTH", "", "password authentication failed")
	if e := toErr(viaTimeout(&store.Conn{Via: "jump"}, other)); e.Message != "password authentication failed" {
		t.Errorf("other errors change: %s", e.Message)
	}
}
