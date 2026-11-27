package store

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/sealdb"
)

// keydataOf is the stored key pair a sealed key path names.
func keydataOf(t *testing.T, path string) []byte {
	t.Helper()
	d, err := DB(false)
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	if err := d.View(context.Background(), func(tx *sealdb.Tx) error {
		r, err := tx.Get(strings.TrimPrefix(path, sealedKeyPrefix))
		b = r.Data
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return b
}

// O-42 for new writes (coordinator, 2026-11-27; Audit to confirm): a server
// that logs in with a key another server uses under another user gets a key
// credential of its own for its user, as the migration makes them, with a
// copy of a key pair komando made. The other server's credential and key
// pair stay exactly as they were.
func TestFormat3KeyForAnotherUser(t *testing.T) {
	migrated(t)
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	rootPath := s.Keys["deploy-root"].Path
	if !strings.HasPrefix(rootPath, sealedKeyPrefix) {
		t.Fatalf("the fixture's key is not one komando made: %q", rootPath)
	}
	pair := keydataOf(t, rootPath)
	before := rawRecords(t)
	if err := Update(Save(), func(s *State) error {
		s.Hosts["web3"] = &Host{Name: "web3", Address: "10.0.0.30", User: "admin", Key: "deploy-root"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after := rawRecords(t)
	for id, m := range before {
		if !maps.EqualFunc(m, after[id], func(a, b json.RawMessage) bool { return string(a) == string(b) }) {
			t.Errorf("record %s (%s) changed", id, m["name"])
		}
	}
	if s, err = Load(); err != nil {
		t.Fatal(err)
	}
	web3 := s.Hosts["web3"]
	if web3.User != "admin" || web3.Key == "" || web3.Key == "deploy-root" {
		t.Fatalf("web3 %+v", web3)
	}
	if s.Hosts["web1"].User != "root" || s.Hosts["web1"].Key != "deploy-root" || s.Keys["deploy-root"].Path != rootPath {
		t.Fatalf("web1 changed: %+v %+v", s.Hosts["web1"], s.Keys["deploy-root"])
	}
	own := s.Keys[web3.Key]
	if own == nil || own.Path == rootPath || string(keydataOf(t, own.Path)) != string(pair) || string(keydataOf(t, rootPath)) != string(pair) {
		t.Fatalf("web3's key %+v is not a copy of the key pair, or the original changed", own)
	}
	// a second server of that user uses the same copy
	if err := Update(Save(), func(s *State) error {
		s.Hosts["web4"] = &Host{Name: "web4", Address: "10.0.0.31", User: "admin", Key: "deploy-root"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if s, err = Load(); err != nil || s.Hosts["web4"].Key != web3.Key {
		t.Fatalf("web4 %+v %v, want key %s", s.Hosts["web4"], err, web3.Key)
	}
	// the copy logs in for its user: the same private key
	mine, err := ReadPrivateKey(s.Keys[web3.Key])
	theirs, err2 := ReadPrivateKey(s.Keys["deploy-root"])
	if err != nil || err2 != nil || len(mine) == 0 || string(mine) != string(theirs) {
		t.Fatalf("the copy's private key: %v %v", err, err2)
	}
	// the audit log names the copy, never a key
	if got := copyEntries(t); len(got) != 1 || got[0]["from"] != "deploy-root" || got[0]["to"] != web3.Key || got[0]["user"] != "admin" {
		t.Fatalf("audit entries %v", got)
	}
	// removing the copy leaves the original
	if err := Update(Save(), func(s *State) error {
		delete(s.Hosts, "web3")
		delete(s.Hosts, "web4")
		delete(s.Keys, web3.Key)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if s, err = Load(); err != nil || s.Keys["deploy-root"] == nil || s.Keys["deploy-root"].Path != rootPath || string(keydataOf(t, rootPath)) != string(pair) {
		t.Fatalf("removing the copy changed the original: %v", err)
	}
	if k, err := ReadPrivateKey(s.Keys["deploy-root"]); err != nil || string(k) != string(theirs) {
		t.Fatalf("the original no longer opens: %v", err)
	}
}

// copyEntries are the audit records of key copies.
func copyEntries(t *testing.T) []map[string]any {
	t.Helper()
	d, err := DB(false)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := d.View(context.Background(), func(tx *sealdb.Tx) error {
		rows, err := tx.Audit(0, 1000)
		for _, r := range rows {
			var m map[string]any
			if json.Unmarshal(r.Data, &m) == nil && m["command"] == "credential.copy" {
				out = append(out, m)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
