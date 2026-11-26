package store

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// migrated is a home whose format-2 fixture store was moved to format 3.
func migrated(t *testing.T) {
	t.Helper()
	format2Store(t)
	if _, err := migrateFormat3(context.Background(), personOpts()); err != nil {
		t.Fatal(err)
	}
	Close()
}

// rawRecords is every record of the store by ID, as stored JSON.
func rawRecords(t *testing.T) map[string]map[string]json.RawMessage {
	t.Helper()
	d, err := DB(false)
	if err != nil {
		t.Fatal(err)
	}
	all := map[string]map[string]json.RawMessage{}
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		for _, typ := range []string{KindHost, KindConn, KindVpn, KindCredential, KindCredStore, KindGroup, KindRecipe, kindSettings} {
			rows, err := tx.List(typ)
			if err != nil {
				return err
			}
			for _, r := range rows {
				var m map[string]json.RawMessage
				if err := json.Unmarshal(r.Data, &m); err != nil {
					return err
				}
				all[r.ID] = m
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return all
}

// T9: a write that changes nothing leaves every record byte for byte.
func TestFormat3RoundTrip(t *testing.T) {
	migrated(t)
	before := rawRecords(t)
	if err := Update(Save(), func(*State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	after := rawRecords(t)
	if len(before) != len(after) {
		t.Fatalf("%d records before, %d after", len(before), len(after))
	}
	for id, m := range before {
		if !maps.EqualFunc(m, after[id], func(a, b json.RawMessage) bool { return string(a) == string(b) }) {
			t.Errorf("record %s changed:\n%s\n%s", id, m, after[id])
		}
	}
}

// T9b (Audit E1-1): a change of one field of an entry that carries fields
// State does not show (a provider, a swarm manager, a credential in an
// outside store) keeps every other field byte for byte.
func TestFormat3WriteKeepsUnmappedFields(t *testing.T) {
	migrated(t)
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{"win1": s.Hosts["win1"].Rec.ID, "ext1": s.Hosts["ext1"].Rec.ID, "web1-swarm": s.Conns["web1-swarm"].Rec.ID}
	before := rawRecords(t)
	err = Update(Save(), func(s *State) error {
		s.Hosts["win1"].Notes = "changed"
		s.Hosts["ext1"].Notes = "changed"
		s.Conns["web1-swarm"].Notes = "changed"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	after := rawRecords(t)
	for name, id := range ids {
		for k, v := range before[id] {
			if k == "notes" || k == "updated_at" {
				continue
			}
			if string(after[id][k]) != string(v) {
				t.Errorf("%s: field %s went from %s to %s", name, k, v, after[id][k])
			}
		}
		if string(after[id]["notes"]) != `"changed"` {
			t.Errorf("%s: notes %s", name, after[id]["notes"])
		}
	}
	for id, m := range before {
		if _, mine := map[string]bool{ids["win1"]: true, ids["ext1"]: true, ids["web1-swarm"]: true}[id]; mine {
			continue
		}
		if !maps.EqualFunc(m, after[id], func(a, b json.RawMessage) bool { return string(a) == string(b) }) {
			t.Errorf("record %s, not changed by the command, changed", id)
		}
	}
}

// Audit E1-2: a write through a host or a service that would change a
// credential another entry also uses is refused, naming every entry that
// uses it; the store is unchanged. One case per field.
func TestFormat3SharedCredentialRefused(t *testing.T) {
	migrated(t)
	err := Update(Save(), func(s *State) error {
		s.Hosts["web3"] = &Host{Name: "web3", Address: "10.0.0.30", User: "root", Key: "deploy-root"}
		s.Conns["pg2"] = &Conn{Name: "pg2", Kind: "postgres", URL: "postgres://app@10.0.0.31:5432/app", PasswordRef: "credential:pg-pass"}
		return nil
	})
	if err != nil {
		t.Fatalf("a second entry naming the same credential: %v", err)
	}
	cases := []struct {
		name   string
		change func(s *State)
		code   string
		names  []string
	}{
		{"the user, through a host", func(s *State) { s.Hosts["web3"].User = "admin" }, "CREDENTIAL_SHARED", []string{"host web1", "host web3"}},
		{"the user, through a service's URL", func(s *State) { s.Conns["pg2"].URL = "postgres://other@10.0.0.31:5432/app" }, "CREDENTIAL_SHARED", []string{"database pg", "database pg2"}},
		{"the value, through a host's password reference", func(s *State) { s.Hosts["web3"].Key, s.Hosts["web3"].PasswordRef = "", "env:OTHER" }, "BAD_REFERENCE", nil},
		{"the value, through a host's password reference in the old spelling", func(s *State) { s.Hosts["web3"].Key, s.Hosts["web3"].PasswordRef = "", "secret:pg-pass" }, "BAD_REFERENCE", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := rawRecords(t)
			err := Update(Save(), func(s *State) error { c.change(s); return nil })
			var oe *out.Error
			if !errorsAs(err, &oe) || oe.Code != c.code || oe.Exit != out.ExitUsage {
				t.Fatalf("got %v", err)
			}
			for _, n := range c.names {
				if !strings.Contains(err.Error(), n) {
					t.Errorf("%q does not name %s", err.Error(), n)
				}
			}
			after := rawRecords(t)
			for id, m := range before {
				if !maps.EqualFunc(m, after[id], func(a, b json.RawMessage) bool { return string(a) == string(b) }) {
					t.Errorf("a refused change wrote record %s", id)
				}
			}
		})
	}
}

func errorsAs(err error, oe **out.Error) bool { return errors.As(err, oe) }

// A key file named on a host gives that host a key credential for the
// file (as the migration does), and never changes a credential another
// entry uses: the host is re-pointed, its neighbour keeps its key.
func TestFormat3KeyFileRepointsOneHost(t *testing.T) {
	migrated(t)
	err := Update(Save(), func(s *State) error {
		s.Hosts["web3"] = &Host{Name: "web3", Address: "10.0.0.30", User: "root", Key: "deploy-root"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = Update(Save(), func(s *State) error {
		s.Hosts["web3"].Key, s.Hosts["web3"].KeyID, s.Hosts["web3"].Identity = "", "", "/home/me/.ssh/other"
		return nil
	})
	if err != nil {
		t.Fatalf("a key file on a host: %v", err)
	}
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	web3, web1 := s.Hosts["web3"], s.Hosts["web1"]
	k := s.Keys[web3.Key]
	if k == nil || k.Path != "/home/me/.ssh/other" || web3.User != "root" {
		t.Fatalf("web3 %q %+v user %q", web3.Key, k, web3.User)
	}
	if web1.Key != "deploy-root" || s.Keys["deploy-root"].Path == "/home/me/.ssh/other" {
		t.Errorf("web1's key changed: %q %+v", web1.Key, s.Keys["deploy-root"])
	}
	// the same file on a second host reuses its credential
	err = Update(Save(), func(s *State) error {
		s.Hosts["web4"] = &Host{Name: "web4", Address: "10.0.0.31", User: "root", Identity: "/home/me/.ssh/other"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := Load(); s.Hosts["web4"].Key != web3.Key {
		t.Errorf("web4 %q, web3 %q", s.Hosts["web4"].Key, web3.Key)
	}
}
