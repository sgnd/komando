package store

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sgnd/komando/internal/sealdb"
)

// putRaw writes one record as another device would (sync): only that
// record changes, no reference is touched.
// editRaw changes the stored JSON of record id, as another device's
// komando would (sync), past this one's writer.
func editRaw(t *testing.T, id string, edit func(m map[string]any)) {
	t.Helper()
	d, err := DB(true)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Update(context.Background(), func(tx *sealdb.Tx) error {
		r, err := tx.Get(id)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(r.Data, &m); err != nil {
			return err
		}
		edit(m)
		b, _ := json.Marshal(m)
		_, err = tx.Put(r.Type, id, b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// renameRaw renames record id as another device would.
func renameRaw(t *testing.T, id, name string) {
	t.Helper()
	editRaw(t, id, func(m map[string]any) { m["name"] = name })
}

func mustLoad(t *testing.T) *State {
	t.Helper()
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Every reference gets the record's ID beside its name when written, and
// a rename that arrives without the references (sync) still reaches them.
func TestReferencesFollowIDs(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Cleanup(Close)
	update(t, func(s *State) {
		s.Keys["deploy"] = &Key{Name: "deploy", Path: "/k/deploy"}
		s.Hosts["bastion"] = &Host{Name: "bastion", Address: "10.0.0.1"}
		s.Vpns["office"] = &Vpn{Name: "office", Kind: "socks", Address: "127.0.0.1:1080"}
		s.Hosts["web"] = &Host{Name: "web", Address: "10.0.0.2", Key: "deploy", Via: "office,bastion,nowhere"}
		s.Conns["db"] = &Conn{Name: "db", Kind: "postgres", URL: "postgres://app@db/app", Via: "bastion"}
	})
	s := mustLoad(t)
	key, bastion, vpn := s.Keys["deploy"], s.Hosts["bastion"], s.Vpns["office"]
	web := s.Hosts["web"]
	if web.KeyID != key.Rec.ID || len(web.ViaIDs) != 3 || web.ViaIDs[0] != vpn.Rec.ID || web.ViaIDs[1] != bastion.Rec.ID || web.ViaIDs[2] != "" {
		t.Fatalf("ids: key %q via %q", web.KeyID, web.ViaIDs)
	}
	if c := s.Conns["db"]; len(c.ViaIDs) != 1 || c.ViaIDs[0] != bastion.Rec.ID {
		t.Fatalf("conn via ids %q", c.ViaIDs)
	}

	// another device renames the key, the jump host and the VPN
	renameRaw(t, key.Rec.ID, "deploy-2026")
	renameRaw(t, bastion.Rec.ID, "jump")
	renameRaw(t, vpn.Rec.ID, "hq")

	s = mustLoad(t)
	if w := s.Hosts["web"]; w.Key != "deploy-2026" || w.Via != "hq,jump,nowhere" {
		t.Errorf("after renames elsewhere: key %q via %q", w.Key, w.Via)
	}
	if c := s.Conns["db"]; c.Via != "jump" {
		t.Errorf("conn via %q", c.Via)
	}
	// a write keeps the followed names and their IDs
	update(t, func(s *State) { s.Hosts["web"].Notes = "x" })
	if w := mustLoad(t).Hosts["web"]; w.Key != "deploy-2026" || w.KeyID != key.Rec.ID {
		t.Errorf("after a write: %q %q", w.Key, w.KeyID)
	}
	// a command that changes the name changes the ID with it
	update(t, func(s *State) {
		s.Keys["other"] = &Key{Name: "other", Path: "/k/other"}
		s.Hosts["web"].Key = "other"
	})
	s = mustLoad(t)
	if w := s.Hosts["web"]; w.Key != "other" || w.KeyID != s.Keys["other"].Rec.ID {
		t.Errorf("key changed by a command: %q %q", w.Key, w.KeyID)
	}
}

// A credential ID that names no record of this store (an export from
// another one) is ignored: the credential's name is used.
func TestReferencesForeignID(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Cleanup(Close)
	update(t, func(s *State) {
		s.Keys["deploy"] = &Key{Name: "deploy", Path: "/k/deploy"}
		s.Hosts["web"] = &Host{Name: "web", Address: "10.0.0.2", Key: "deploy"}
	})
	id := mustLoad(t).Hosts["web"].Rec.ID
	editRaw(t, id, func(m map[string]any) { m["credential_id"] = "0123456789abcdef0123456789abcdef" })
	if w := mustLoad(t).Hosts["web"]; w.Key != "deploy" {
		t.Errorf("an unknown ID changed the name: %q", w.Key)
	}
}
