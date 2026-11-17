package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

func TestRenameURLSecretRefs(t *testing.T) {
	for _, c := range []struct {
		in, from, to, want string
		hit                bool
	}{
		{"registry://u@reg.lan?ca=secret:old", "old", "new", "registry://u@reg.lan?ca=secret:new", true},
		// the other options keep their order and escaping; the fragment stays
		{"x://h/p?a=1&ca=secret%3Aold&b=%2F#f", "old", "new", "x://h/p?a=1&ca=secret:new&b=%2F#f", true},
		{"x://h?ca=secret:old&key=secret:old", "old", "new", "x://h?ca=secret:new&key=secret:new", true},
		// only the exact name
		{"x://h?ca=secret:old-2", "old", "new", "x://h?ca=secret:old-2", false},
		{"x://h?ca=env:old", "old", "new", "x://h?ca=env:old", false},
		{"x://h/secret:old", "old", "new", "x://h/secret:old", false},
		{"x://h#?ca=secret:old", "old", "new", "x://h#?ca=secret:old", false},
		{"x://h", "old", "new", "x://h", false},
		// to "" only looks
		{"x://h?ca=secret:old", "old", "", "x://h?ca=secret:old", true},
	} {
		got, hit := renameURLSecretRefs(c.in, c.from, c.to)
		if got != c.want || hit != c.hit {
			t.Errorf("%s: got %s %v, want %s %v", c.in, got, hit, c.want, c.hit)
		}
	}
	refs := urlSecretRefs("registry://u@h?tls=&ca=secret:reg-ca")
	if len(refs) != 1 || refs[0] != (urlSecretRef{"ca", "reg-ca"}) {
		t.Errorf("refs %+v", refs)
	}
}

// A secret that only a conn URL option names (a registry's
// ?ca=secret:NAME) counts as used everywhere: secret list, rm, mv, export
// and doctor.
func TestSecretRefInConnURL(t *testing.T) {
	invHome(t)
	setSecret(t, "reg-ca", "-----BEGIN CERTIFICATE-----")
	const url = "registry://deploy@registry.lan?ca=secret:reg-ca"
	if err := store.Update(store.Save(), func(s *store.State) error {
		s.Conns = map[string]*store.Conn{"reg": {Name: "reg", Kind: "registry", URL: url, Protected: true}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	d := mustRun(t, "secret", "list")
	row := d["secrets"].([]any)[0].(map[string]any)
	if u := row["used_by"].([]any); len(u) != 1 || u[0] != "conn reg" {
		t.Errorf("secret list used_by: %v", row)
	}
	wantCode(t, "SECRET_IN_USE", "secret", "rm", "reg-ca")
	wantCode(t, "SECRET_IN_USE", "secret", "rm", "reg-ca", "--dry-run")

	exp := mustRun(t, "export")
	if n := exp["secrets_needed"].([]any); len(n) != 1 || n[0] != "reg-ca" {
		t.Errorf("export secrets_needed: %v", n)
	}

	d = mustRun(t, "secret", "mv", "reg-ca", "registry-ca", "--dry-run")
	if u := d["would_update"].([]any); len(u) != 1 || u[0] != "conn reg" {
		t.Errorf("mv dry run: %v", d)
	}
	st, _ := loadState()
	if st.Conns["reg"].URL != url {
		t.Fatalf("the dry run changed the URL: %s", st.Conns["reg"].URL)
	}

	d = mustRun(t, "secret", "mv", "reg-ca", "registry-ca")
	if u := d["updated"].([]any); len(u) != 1 || u[0] != "conn reg" {
		t.Errorf("mv: %v", d)
	}
	st, _ = loadState()
	if got := st.Conns["reg"].URL; got != "registry://deploy@registry.lan?ca=secret:registry-ca" {
		t.Errorf("URL after mv: %s", got)
	}

	// doctor: quiet while the secret is there, a warning once it is gone
	for _, c := range inventoryChecks(tcl, st) {
		if c.Name == "conn:reg" {
			t.Errorf("doctor: %+v", c)
		}
	}
	if err := store.Update(store.Save(), func(s *store.State) error {
		s.Conns["reg"].URL = "registry://deploy@registry.lan?ca=secret:nope"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, _ = loadState()
	found := false
	for _, c := range inventoryChecks(tcl, st) {
		if c.Name == "conn:reg" && c.Warning && strings.Contains(c.Detail, "ca secret:nope is not in the vault") {
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
