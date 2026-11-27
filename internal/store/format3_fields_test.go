package store

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/sealdb"
)

// fillAll sets every exported field of the struct v points to: a value
// from set when it names the field, else a non-zero value of the field's
// kind. A field of a kind it does not know fails the test, so a new field
// is never left at zero.
func fillAll(t *testing.T, v any, set map[string]any) {
	t.Helper()
	rv := reflect.ValueOf(v).Elem()
	for i := range rv.NumField() {
		f, sf := rv.Field(i), rv.Type().Field(i)
		if !sf.IsExported() {
			continue
		}
		if x, ok := set[sf.Name]; ok {
			f.Set(reflect.ValueOf(x))
			continue
		}
		switch {
		case f.Kind() == reflect.String:
			f.SetString("x-" + sf.Name)
		case f.Kind() == reflect.Int:
			f.SetInt(7)
		case f.Kind() == reflect.Bool:
			f.SetBool(true)
		case f.Type() == reflect.TypeOf([]string{}):
			f.Set(reflect.ValueOf([]string{"x-" + sf.Name}))
		case f.Type() == reflect.TypeOf(map[string]string{}):
			f.Set(reflect.ValueOf(map[string]string{"k": "x-" + sf.Name}))
		case f.Type() == reflect.TypeOf(time.Time{}):
			f.Set(reflect.ValueOf(time.Date(2026, 11, 26, 1, 2, 3, 0, time.UTC)))
		case f.Kind() == reflect.Pointer && f.Type().Elem().Kind() == reflect.Struct:
			p := reflect.New(f.Type().Elem())
			fillAll(t, p.Interface(), nil)
			f.Set(p)
		default:
			t.Fatalf("%s.%s: a field of kind %s the test cannot fill; teach fillAll", rv.Type().Name(), sf.Name, f.Type())
		}
	}
	for i := range rv.NumField() {
		if rv.Type().Field(i).IsExported() && rv.Field(i).IsZero() {
			t.Fatalf("%s.%s is still zero", rv.Type().Name(), rv.Type().Field(i).Name)
		}
	}
}

// Audit C1: every exported field of a host, a service and a VPN record
// survives a write through State that changes one other field. A field
// added to HostV3, ServiceV3 or VpnV3 fails here until State maps it or
// the writer keeps it (the merge of Audit E1-1).
func TestFormat3EveryFieldSurvivesAWrite(t *testing.T) {
	sealedHome(t)
	if _, err := DB(true); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	format3Write(t, func(tx *sealdb.Tx) error {
		for _, name := range []string{"c-login", "c-sudo", "c-psk", "c-config", "c-svc"} {
			id, err := putJSON(tx, KindCredential, "", &Credential{Name: name, Kind: CredToken, User: "x-User"})
			if err != nil {
				return err
			}
			ids[name] = id
		}
		jump, err := putJSON(tx, KindHost, "", &HostV3{Name: "jump", Provider: "ssh", Address: "10.0.0.9"})
		if err != nil {
			return err
		}
		h := &HostV3{}
		fillAll(t, h, map[string]any{
			"Name": "full", "Provider": "winrm", "Credential": "c-login", "CredentialID": ids["c-login"],
			"SudoCredential": "c-sudo", "Via": "jump", "ViaIDs": []string{jump},
		})
		s := &ServiceV3{}
		fillAll(t, s, map[string]any{
			"Name": "svc", "Type": "database", "Provider": "postgres", "URL": "postgres://10.0.0.5:5432/app",
			"Credential": "c-svc", "Via": "jump", "ViaIDs": []string{jump}, "ManagerID": jump,
		})
		v := &VpnV3{}
		fillAll(t, v, map[string]any{
			"Name": "vpn", "Credential": "c-login", "PSKCredential": "c-psk", "ConfigCredential": "c-config",
		})
		for typ, rec := range map[string]any{KindHost: h, KindConn: s, KindVpn: v} {
			id, err := putJSON(tx, typ, "", rec)
			if err != nil {
				return err
			}
			ids[typ] = id
		}
		return nil
	})
	before := rawRecords(t)
	err := Update(Save(), func(s *State) error {
		s.Hosts["full"].Notes = "changed"
		s.Conns["svc"].Notes = "changed"
		s.Vpns["vpn"].Notes = "changed"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	after := rawRecords(t)
	for _, typ := range []string{KindHost, KindConn, KindVpn} {
		id := ids[typ]
		for k, v := range before[id] {
			if k == "notes" {
				continue
			}
			if string(after[id][k]) != string(v) {
				t.Errorf("%s: field %s went from %s to %s", typ, k, v, after[id][k])
			}
		}
		var notes string
		if err := json.Unmarshal(after[id]["notes"], &notes); err != nil || notes != "changed" {
			t.Errorf("%s: notes %s", typ, after[id]["notes"])
		}
	}
}
