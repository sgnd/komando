package store

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// The migration keeps a field that named an outside value (env:VAR,
// op://...) and is no login (an env value, a service option) as a
// credential in a credential store. Such a credential
// reads its value from the reference it was made from; a credential with
// a value of its own, a key, or no credential at all reads nothing there.
func TestOutsideRefOfMigrated(t *testing.T) {
	migrated(t)
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string][2]string{"ext1": {"WEB_PW", "env:WEB_PW"}, "vh": {"APP_PW", "vault:kv/app#pw"}} {
		name, ok := strings.CutPrefix(s.Hosts[host].Env[want[0]], "credential:")
		if !ok || name == "" {
			t.Fatalf("%s names %q", host, s.Hosts[host].Env[want[0]])
		}
		if got, err := OutsideRefOf(name); err != nil || got != want[1] {
			t.Fatalf("%s: credential %s reads %q %v, want %s", host, name, got, err, want)
		}
	}
	name := strings.TrimPrefix(s.Hosts["win1"].PasswordRef, "credential:")
	if got, err := OutsideRefOf(name); name == "" || err != nil || got != "" {
		t.Fatalf("win1's credential %q with its own value reads %q %v", name, got, err)
	}
	for _, name := range []string{"nothing", "deploy-root"} {
		if got, err := OutsideRefOf(name); err != nil || got != "" {
			t.Fatalf("%s reads %q %v", name, got, err)
		}
	}
}

// CLI-5, 2026-11-26: a command makes no credential store item. An outside
// reference on a field of a host, a service, a VPN or a key is refused
// with a usage error; nothing is written.
func TestFormat3OutsideRefRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(s *State)
	}{
		{"host password", func(s *State) { s.Hosts["web"] = &Host{Name: "web", Address: "a", PasswordRef: "env:WEB_PW"} }},
		{"host sudo", func(s *State) { s.Hosts["web"] = &Host{Name: "web", Address: "a", User: "u", SudoRef: "file:/tmp/pw"} }},
		{"service password", func(s *State) {
			s.Conns["db"] = &Conn{Name: "db", Kind: "postgres", URL: "postgres://u@h/d", PasswordRef: "op://ops/db/password"}
		}},
		{"vpn key", func(s *State) { s.Vpns["office"] = &Vpn{Name: "office", Kind: "wireguard", KeyRef: "vault:kv/wg#key"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealedHome(t)
			fakeKeys(t)
			err := Update(Save(), func(s *State) error { tc.set(s); return nil })
			var oe *out.Error
			if !errorsAs(err, &oe) || oe.Code != "REFERENCE_UNSUPPORTED" || oe.Exit != out.ExitUsage || !strings.Contains(oe.Hint, "credential:NAME") {
				t.Fatalf("got %v, want REFERENCE_UNSUPPORTED naming credential:NAME", err)
			}
			s, err := Load()
			if err != nil || len(s.Hosts)+len(s.Conns)+len(s.Vpns) != 0 {
				t.Fatalf("something was written: %v", err)
			}
		})
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
			if !errorsAs(err, &oe) || oe.Code != "REFERENCE_UNSUPPORTED" || !strings.Contains(oe.Hint, "credential:db-pw") {
				t.Fatalf("got %v, want REFERENCE_UNSUPPORTED naming credential:db-pw", err)
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

// CredentialRef is the one check of a reference to a credential, shared by
// the store's writer and the CLI's flags: empty and credential:NAME pass,
// the old spelling and an outside store stop with REFERENCE_UNSUPPORTED. Anything
// else is not a reference; the caller says what it wants instead.
// outsideFixLine is the fix the refusal of an outside store names, spelled
// out here so that a change to CredentialFix shows in this test.
const outsideFixLine = "save the secret as a credential with `komando secret set NAME`, then use credential:NAME"

func TestCredentialRef(t *testing.T) {
	for _, tc := range []struct {
		ref, hint string
	}{
		{"", ""},
		{"credential:db-pw", ""},
		{"hunter2", ""},
		{"secret:db-pw", "credential:db-pw"},
		{"env:DB_PW", "credential:NAME"},
		{"file:/tmp/pw", "credential:NAME"},
		{"op://ops/db/password", "credential:NAME"},
		{"vault:kv/app#pw", "credential:NAME"},
		{"kdbx:~/t.kdbx#a", "credential:NAME"},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			err := CredentialRef("--password-ref", tc.ref)
			if tc.hint == "" {
				if err != nil {
					t.Fatalf("got %v, want nil", err)
				}
				return
			}
			var oe *out.Error
			if !errorsAs(err, &oe) || oe.Code != "REFERENCE_UNSUPPORTED" || oe.Exit != out.ExitUsage ||
				!strings.Contains(oe.Hint, tc.hint) || !strings.Contains(oe.Message, "--password-ref") {
				t.Fatalf("got %v, want REFERENCE_UNSUPPORTED on --password-ref naming %s", err, tc.hint)
			}
			if strings.Contains(oe.Message+oe.Hint, tc.ref) && tc.ref != "secret:db-pw" {
				t.Fatalf("the message repeats the reference: %v", err)
			}
			// condition 2 of C547: the refusal of an outside store names
			// the fix in one line
			if tc.hint == "credential:NAME" && oe.Hint != outsideFixLine {
				t.Fatalf("hint %q, want the one line %q", oe.Hint, outsideFixLine)
			}
		})
	}
}
