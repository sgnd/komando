package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// credentialsOf is every credential record of the store by name.
func credentialsOf(t *testing.T) map[string]Credential {
	t.Helper()
	cs := map[string]Credential{}
	for _, m := range rawRecords(t) {
		if _, ok := m["kind"]; !ok {
			continue
		}
		b, _ := json.Marshal(m)
		var c Credential
		if err := json.Unmarshal(b, &c); err != nil || c.Name == "" {
			continue
		}
		cs[c.Name] = c
	}
	return cs
}

// An outside reference given on a host, a service or a VPN (env:VAR,
// file:PATH, op://...) is kept as a credential in a credential store, as
// the migration keeps one: the field names that credential, and writing
// the entry again makes no second one.
func TestFormat3OutsideRefBecomesCredential(t *testing.T) {
	sealedHome(t)
	fakeKeys(t)
	if err := Update(Save(), func(s *State) error {
		s.Hosts["web"] = &Host{Name: "web", Address: "10.0.0.5", User: "app", PasswordRef: "env:KOMANDO_E1_PW"}
		s.Conns["db"] = &Conn{Name: "db", Kind: "postgres", URL: "postgres://ro@db.internal/sales", PasswordRef: "op://ops/db/password"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	ref := s.Hosts["web"].PasswordRef
	name, ok := strings.CutPrefix(ref, "credential:")
	if !ok || name == "" {
		t.Fatalf("host password ref %q, want credential:NAME", ref)
	}
	got, err := OutsideRefOf(name)
	if err != nil || got != "env:KOMANDO_E1_PW" {
		t.Fatalf("host credential %s reads %q %v, want env:KOMANDO_E1_PW", name, got, err)
	}
	if c := credentialsOf(t)[name]; c.User != "app" || c.Store == "" || c.Item != "KOMANDO_E1_PW" || c.Value != nil {
		t.Fatalf("host credential: %+v", c)
	}
	cname := strings.TrimPrefix(s.Conns["db"].PasswordRef, "credential:")
	if got, err := OutsideRefOf(cname); err != nil || got != "op://ops/db/password" {
		t.Fatalf("service credential %s reads %q %v", cname, got, err)
	}
	n := len(credentialsOf(t))
	if err := Update(Save(), func(s *State) error {
		s.Hosts["web"].Address = "10.0.0.6"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if m := len(credentialsOf(t)); m != n {
		t.Fatalf("%d credentials after a second write, %d before", m, n)
	}
}

// A credential that holds its own value, or none of an outside store, is
// no outside reference.
func TestOutsideRefOfOwnValue(t *testing.T) {
	sealedHome(t)
	fakeKeys(t)
	if got, err := OutsideRefOf("nothing"); err != nil || got != "" {
		t.Fatal("a missing credential reads as an outside reference")
	}
}

// The spelling format 2 used for a reference (secret:NAME) is refused on
// every reference field, with a usage error that names credential:NAME;
// nothing is written.
func TestFormat3OldSpellingRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(s *State)
	}{
		{"host password", func(s *State) { s.Hosts["web"] = &Host{Name: "web", Address: "a", PasswordRef: "secret:db-pw"} }},
		{"host sudo", func(s *State) { s.Hosts["web"] = &Host{Name: "web", Address: "a", User: "u", SudoRef: "secret:db-pw"} }},
		{"service password", func(s *State) {
			s.Conns["db"] = &Conn{Name: "db", Kind: "postgres", URL: "postgres://u@h/d", PasswordRef: "secret:db-pw"}
		}},
		{"vpn psk", func(s *State) { s.Vpns["office"] = &Vpn{Name: "office", Kind: "wireguard", PSKRef: "secret:db-pw"} }},
		// fields F10 reads on load: a write that put the old spelling there
		// would leave a store that no longer opens
		{"host env", func(s *State) {
			s.Hosts["web"] = &Host{Name: "web", Address: "a", Env: map[string]string{"PG": "secret:db-pw"}}
		}},
		{"service option", func(s *State) {
			s.Conns["db"] = &Conn{Name: "db", Kind: "postgres", URL: "postgres://u@h/d", Options: map[string]string{"ca": "secret:db-pw"}}
		}},
		{"service URL query", func(s *State) {
			s.Conns["db"] = &Conn{Name: "db", Kind: "postgres", URL: "postgres://u@h/d?sslrootcert=secret:db-pw"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealedHome(t)
			fakeKeys(t)
			err := Update(Save(), func(s *State) error { tc.set(s); return nil })
			var oe *out.Error
			if !errorsAs(err, &oe) || oe.Code != "BAD_REFERENCE" || !strings.Contains(oe.Hint, "credential:db-pw") {
				t.Fatalf("got %v, want BAD_REFERENCE naming credential:db-pw", err)
			}
			s, err := Load()
			if err != nil || len(s.Hosts)+len(s.Conns)+len(s.Vpns) != 0 {
				t.Fatalf("something was written: %v", err)
			}
		})
	}
}

func TestOldReference(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		old      bool
	}{
		{"secret:db", "credential:db", true},
		{"secret:a.b-c_d", "credential:a.b-c_d", true},
		{"secret:", "", false},
		{"secret:a b", "", false},
		{"credential:db", "", false},
		{"secretary", "", false},
		{"env:secret:x", "", false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, old := OldReference(tc.in)
			if old != tc.old || got != tc.want {
				t.Fatalf("OldReference(%q) = %q %v, want %q %v", tc.in, got, old, tc.want, tc.old)
			}
		})
	}
}
