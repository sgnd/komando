package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// sentinel marks every secret value of the test store; no report, error or
// notice may hold it.
const sentinel = "VALUE-SENTINEL"

func secretValue(name string) string { return sentinel + "-" + name }

// testSecrets are the vault secrets of the format-2 store.
var testSecrets = []string{
	"pg-pass", "win-pw", "win-ca", "web2-pw", "pg-ca", "nats-creds", "k8s-kubeconfig",
	"wg-key", "wg-psk", "ts-auth", "deploy-pp", "unused-token", "sudo-pw", "shared-pw", "winssh-pw", "s3-secret", "s3-sse", "ovpn-config", ApprovalSeedName,
}

// format2Store makes a sealed home of format 2 with every kind the store
// keeps (design section 1) and returns the home.
func format2Store(t *testing.T) string {
	t.Helper()
	home := sealedHome(t)
	d, err := DB(true)
	if err != nil {
		t.Fatal(err)
	}
	master, err := MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	vc, err := newValueCipher(master)
	if err != nil {
		t.Fatal(err)
	}
	var keydataID string
	err = d.Update(context.Background(), func(tx *sealdb.Tx) error {
		for _, n := range testSecrets {
			v, err := vc.seal(n, []byte(secretValue(n)))
			if err != nil {
				return err
			}
			b, _ := json.Marshal(map[string]any{"name": n, "nonce": v.Nonce, "data": v.Data, "updated_at": time.Now().UTC()})
			if _, err := tx.Put("secret", "", b); err != nil {
				return err
			}
		}
		r, err := tx.Put(keyDataType, "", []byte(`{"private":"cHJpdmF0ZQ==","public":"cHVibGlj"}`))
		if err != nil {
			return err
		}
		keydataID = r.ID
		for _, rec := range [][2]string{
			{KindHostCA, `{"name":"corp-ca","key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA","hosts":["*.corp"]}`},
			{KindPin, `{"addr":"10.0.0.5:22","keys":["ssh-ed25519 AAAA"]}`},
			{KindPinRevoked, `{"keys":["ssh-ed25519 BBBB"]}`},
			{vpnStateType, `{"vpn":"tail","values":{"node":"bm9kZQ=="}}`},
		} {
			if _, err := tx.Put(rec[0], "", []byte(rec[1])); err != nil {
				return err
			}
		}
		for _, e := range []string{`{"command":"host.add"}`, `{"command":"exec"}`} {
			if err := tx.AppendAudit([]byte(e)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = Update(Save(), func(s *State) error {
		s.Settings.ExtraDenyPattern = []string{"rm -rf /srv"}
		s.Keys["deploy"] = &Key{Name: "deploy", Path: sealedKeyPrefix + keydataID, Type: "ed25519", PassphraseRef: "secret:deploy-pp", Managed: true}
		s.Keys["solo"] = &Key{Name: "solo", Path: "/home/me/.ssh/id_solo", Type: "ed25519"}
		s.Hosts["web1"] = &Host{Name: "web1", Address: "10.0.0.1", User: "root", Key: "deploy", Groups: []string{"Prod"}, Tags: []string{"swarm", "edge"},
			Labels: map[string]string{"team": "core", "note": "secret:not-a-ref"},
			Env:    map[string]string{"PG": "secret:pg-pass", "MODE": "live"}, SudoRef: "secret:sudo-pw", Protected: true}
		s.Hosts["db1"] = &Host{Name: "db1", Address: "10.0.0.2", User: "app", Key: "deploy", Groups: []string{"prod"}}
		s.Hosts["win1"] = &Host{Name: "win1", Address: "10.0.0.3", User: `DOMAIN\admin`, PasswordRef: "secret:win-pw",
			Transport: TransportWinRM, WinRMOpts: &WinRMOpts{CA: "secret:win-ca"}}
		s.Hosts["web2"] = &Host{Name: "web2", Address: "10.0.0.4", User: "root", Key: "solo", PasswordRef: "secret:web2-pw"}
		s.Hosts["agent1"] = &Host{Name: "agent1", Address: "10.0.0.6", User: "ops"}
		s.Hosts["ask1"] = &Host{Name: "ask1", Address: "10.0.0.7", User: "admin", Login: LoginAsk}
		s.Hosts["h3"] = &Host{Name: "h3", Address: "10.0.0.10", User: "alice", PasswordRef: "secret:shared-pw", Env: map[string]string{"TOKEN": "secret:shared-pw"}}
		s.Hosts["h4"] = &Host{Name: "h4", Address: "10.0.0.11", User: "bob", PasswordRef: "secret:shared-pw"}
		s.Hosts["idh"] = &Host{Name: "idh", Address: "10.0.0.12", User: "deploy", Identity: "/home/me/.ssh/id_work"}
		s.Hosts["winssh"] = &Host{Name: "winssh", Address: "10.0.0.13", User: "Administrator", OS: OSWindows, PasswordRef: "secret:winssh-pw"}
		s.Hosts["vh"] = &Host{Name: "vh", Address: "10.0.0.14", User: "root", PasswordRef: "vault:kv/app#pw"}
		s.Conns["s3b"] = &Conn{Name: "s3b", Kind: "s3", URL: "s3://AKIAEXAMPLE@bucket?region=eu-west-1", PasswordRef: "secret:s3-secret",
			Options: map[string]string{"sse_key": "secret:s3-sse", "class": "STANDARD"}}
		s.Conns["mydb"] = &Conn{Name: "mydb", Kind: "mysql", URL: "mysql://admin@10.0.0.20:3306/app", Login: LoginAsk}
		s.Vpns["ovpn"] = &Vpn{Name: "ovpn", Kind: "openvpn", User: "me", ConfigRef: "secret:ovpn-config", KeyRef: "op://Private/vpn/password"}
		s.Hosts["ext1"] = &Host{Name: "ext1", Address: "10.0.0.8", User: "root", PasswordRef: "env:WEB_PW"}
		s.Conns["pg"] = &Conn{Name: "pg", Kind: "postgres", URL: "postgres://app@10.0.0.5:5432/app?ca=secret:pg-ca", PasswordRef: "secret:pg-pass", Groups: []string{"Prod"}, Protected: true}
		s.Conns["bus"] = &Conn{Name: "bus", Kind: "nats", URL: "nats://10.0.0.9:4222?creds=secret:nats-creds"}
		s.Conns["k8s"] = &Conn{Name: "k8s", Kind: "k8s", URL: "k8s://api.corp:6443", PasswordRef: "secret:k8s-kubeconfig"}
		s.Vpns["wg"] = &Vpn{Name: "wg", Kind: "wireguard", KeyRef: "secret:wg-key", PSKRef: "secret:wg-psk", MFA: true}
		s.Vpns["tail"] = &Vpn{Name: "tail", Kind: "tailscale", KeyRef: "secret:ts-auth"}
		s.Snippets["r1"] = &Snippet{Name: "r1", Command: "echo secret:abc"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return home
}

// notices collects what the store tells the person.
func notices(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	old := Notice
	Notice = func(msg string) { b.WriteString(msg + "\n") }
	t.Cleanup(func() { Notice = old })
	return &b
}

func personOpts() migrate3Opts {
	return migrate3Opts{person: true, alive: func(int, string) bool { return false }}
}

func formatNow(t *testing.T) string {
	t.Helper()
	m, err := sealdb.Peek(context.Background(), DBPath())
	if err != nil {
		t.Fatal(err)
	}
	return m["format"]
}

func fileSum(t *testing.T) [32]byte {
	t.Helper()
	b, err := os.ReadFile(DBPath())
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

// byName is the read-back records of one type by name.
func byName[T any](t *testing.T, recs []record3, typ string) map[string]*T {
	t.Helper()
	m := map[string]*T{}
	for _, r := range recs {
		if r.typ != typ {
			continue
		}
		v, ok := r.data.(*T)
		if !ok {
			t.Fatalf("%s %s is %T", typ, r.name, r.data)
		}
		m[r.name] = v
	}
	return m
}

func TestMigrate3(t *testing.T) {
	format2Store(t)
	err := UpdateRuntime(Save(), func(s *State) error {
		s.Sessions["wg"] = &VpnSession{Vpn: "wg", PID: 9999, ProcStart: "gone"} // not alive
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	said := notices(t)
	res, err := migrateFormat3(context.Background(), personOpts())
	if err != nil {
		t.Fatal(err)
	}
	if f := formatNow(t); f != "3" {
		t.Fatalf("format %s after the migration", f)
	}
	hosts := byName[HostV3](t, res.readBack, KindHost)
	conns := byName[ServiceV3](t, res.readBack, KindConn)
	vpns := byName[VpnV3](t, res.readBack, KindVpn)
	creds := byName[Credential](t, res.readBack, KindCredential)

	t.Run("one key, two users: two credentials with their own key copy", func(t *testing.T) {
		if hosts["web1"].Credential != "deploy-root" || hosts["db1"].Credential != "deploy-app" {
			t.Fatalf("web1 %q, db1 %q", hosts["web1"].Credential, hosts["db1"].Credential)
		}
		a, b := creds["deploy-root"], creds["deploy-app"]
		if a == nil || b == nil || a.User != "root" || b.User != "app" || a.Kind != CredKey {
			t.Fatalf("credentials %+v %+v", a, b)
		}
		if a.Key.Path == b.Key.Path || !strings.HasPrefix(a.Key.Path, sealedKeyPrefix) || !strings.HasPrefix(b.Key.Path, sealedKeyPrefix) {
			t.Errorf("key copies %q %q", a.Key.Path, b.Key.Path)
		}
		if a.Key.Passphrase != "deploy-pp" || b.Key.Passphrase != "deploy-pp" {
			t.Errorf("passphrase %q %q", a.Key.Passphrase, b.Key.Passphrase)
		}
		if creds["deploy"] != nil {
			t.Error("the old name deploy still names a credential")
		}
	})
	t.Run("one password, two users: values sealed again under the new names", func(t *testing.T) {
		if hosts["h3"].Credential != "shared-pw-alice" || hosts["h4"].Credential != "shared-pw-bob" {
			t.Fatalf("h3 %q, h4 %q", hosts["h3"].Credential, hosts["h4"].Credential)
		}
		if c := creds["shared-pw-bob"]; c == nil || c.User != "bob" || c.Value == nil {
			t.Fatalf("shared-pw-bob %+v", c)
		}
		// the env use is no login: the value keeps its name as a token
		if c := creds["shared-pw"]; c == nil || c.Kind != CredToken || hosts["h3"].Env["TOKEN"] != "credential:shared-pw" {
			t.Errorf("shared-pw %+v, env %v", c, hosts["h3"].Env)
		}
	})
	t.Run("a domain user keeps the secret's name and holds the user", func(t *testing.T) {
		if c := creds["win-pw"]; c == nil || c.User != `DOMAIN\admin` || c.Kind != CredPassword || hosts["win1"].Credential != "win-pw" {
			t.Fatalf("win-pw %+v, win1 %q", c, hosts["win1"].Credential)
		}
		if hosts["win1"].Provider != "winrm" || hosts["win1"].WinRMOpts.CA != "credential:win-ca" {
			t.Errorf("win1 %+v", hosts["win1"])
		}
	})
	t.Run("references read credential:NAME", func(t *testing.T) {
		if hosts["web1"].Env["PG"] != "credential:pg-pass" || hosts["web1"].Env["MODE"] != "live" {
			t.Errorf("env %v", hosts["web1"].Env)
		}
		if hosts["web1"].SudoCredential != "sudo-pw" {
			t.Errorf("sudo %q", hosts["web1"].SudoCredential)
		}
		if conns["pg"].URL != "postgres://10.0.0.5:5432/app?ca=credential:pg-ca" || conns["pg"].Credential != "pg-pass" {
			t.Errorf("pg %+v", conns["pg"])
		}
		if creds["pg-pass"].User != "app" {
			t.Errorf("the URL's user did not move: %+v", creds["pg-pass"])
		}
		if conns["bus"].URL != "nats://10.0.0.9:4222?creds=credential:nats-creds" {
			t.Errorf("bus %s", conns["bus"].URL)
		}
		if v := vpns["wg"]; v.Credential != "wg-key" || v.PSKCredential != "wg-psk" || v.Provider != "wireguard" || !v.MFA {
			t.Errorf("wg %+v", v)
		}
	})
	t.Run("typed entries", func(t *testing.T) {
		for name, want := range map[string][2]string{"pg": {"database", "postgres"}, "bus": {"queue", "nats"}, "k8s": {"cluster", "kubernetes"}} {
			if c := conns[name]; c.Type != want[0] || c.Provider != want[1] {
				t.Errorf("%s: %s %s", name, c.Type, c.Provider)
			}
		}
		if creds["k8s-kubeconfig"].Kind != CredToken {
			t.Errorf("kubeconfig kind %s", creds["k8s-kubeconfig"].Kind)
		}
	})
	t.Run("swarm tag becomes a swarm entry", func(t *testing.T) {
		s := conns["web1-swarm"]
		if s == nil || s.Type != "cluster" || s.Provider != "swarm" || s.Manager != "web1" || s.ManagerID == "" {
			t.Fatalf("swarm %+v", s)
		}
		if slices.Contains(hosts["web1"].Tags, "swarm") || !slices.Contains(hosts["web1"].Tags, "edge") {
			t.Errorf("tags %v", hosts["web1"].Tags)
		}
	})
	t.Run("ssh-agent, typed password and outside store logins", func(t *testing.T) {
		if c := creds[hosts["agent1"].Credential]; c == nil || !c.Key.Agent || c.User != "ops" || hosts["agent1"].Credential != "agent1-agent" {
			t.Errorf("agent1 %q %+v", hosts["agent1"].Credential, c)
		}
		if c := creds[hosts["ask1"].Credential]; c == nil || !c.Ask || c.User != "admin" || c.Value != nil {
			t.Errorf("ask1 %q %+v", hosts["ask1"].Credential, c)
		}
		c := creds[hosts["ext1"].Credential]
		if c == nil || c.Store != "env" || c.Item != "WEB_PW" || c.User != "root" || c.Value != nil {
			t.Fatalf("ext1 %q %+v", hosts["ext1"].Credential, c)
		}
		stores := byName[CredentialStore](t, res.readBack, KindCredStore)
		if s := stores["env"]; s == nil || s.Provider != "env" {
			t.Errorf("stores %v", stores)
		}
	})
	t.Run("a host with key and password keeps the key; the report lists it", func(t *testing.T) {
		if hosts["web2"].Credential != "solo" || creds["web2-pw"] == nil {
			t.Errorf("web2 %q", hosts["web2"].Credential)
		}
		if !slices.Contains(res.report.KeyAndPassword, "web2") {
			t.Errorf("report %v", res.report.KeyAndPassword)
		}
	})
	t.Run("groups by record ID, any case merged", func(t *testing.T) {
		groups := byName[Group](t, res.readBack, KindGroup)
		g := groups["Prod"]
		if len(groups) != 1 || g == nil || len(g.Members) != 3 {
			t.Fatalf("groups %v", groups)
		}
	})
	t.Run("the approval seed is no credential", func(t *testing.T) {
		if creds[ApprovalSeedName] != nil {
			t.Error("the seed is a credential")
		}
		if n := countType(res.readBack, KindApprovalSeed); n != 1 {
			t.Errorf("%d seed records", n)
		}
	})
	t.Run("internal records carried", func(t *testing.T) {
		for typ, want := range map[string]int{vpnStateType: 1, keyDataType: 2, KindHostCA: 1, KindPin: 1, KindPinRevoked: 1, KindRecipe: 1, "secret": 0, KindKey: 0} {
			if n := countType(res.readBack, typ); n != want {
				t.Errorf("%s: %d records, want %d", typ, n, want)
			}
		}
	})
	t.Run("labels stay as written", func(t *testing.T) {
		if l := hosts["web1"].Labels; l["team"] != "core" || l["note"] != "secret:not-a-ref" {
			t.Errorf("labels %v", l)
		}
	})
	t.Run("a key file with no key record", func(t *testing.T) {
		c := creds[hosts["idh"].Credential]
		if hosts["idh"].Credential != "id-work-deploy" || c == nil || c.Kind != CredKey || c.User != "deploy" || c.Key.Path != "/home/me/.ssh/id_work" {
			t.Errorf("idh %q %+v", hosts["idh"].Credential, c)
		}
	})
	t.Run("Windows over OpenSSH stays ssh", func(t *testing.T) {
		h := hosts["winssh"]
		if h.Provider != "ssh" || h.OS != OSWindows || h.Credential != "winssh-pw" || creds["winssh-pw"].User != "Administrator" {
			t.Errorf("winssh %+v", h)
		}
	})
	t.Run("a conn option that names a secret", func(t *testing.T) {
		c := conns["s3b"]
		if c.Options["sse_key"] != "credential:s3-sse" || c.Options["class"] != "STANDARD" || c.URL != "s3://bucket?region=eu-west-1" {
			t.Errorf("s3b %+v", c)
		}
		if creds["s3-secret"].User != "AKIAEXAMPLE" || creds["s3-sse"].Kind != CredToken {
			t.Errorf("s3 credentials %+v %+v", creds["s3-secret"], creds["s3-sse"])
		}
	})
	t.Run("a conn whose password a person types", func(t *testing.T) {
		c := creds[conns["mydb"].Credential]
		if conns["mydb"].Credential != "mydb-ask" || c == nil || !c.Ask || c.User != "admin" || c.Value != nil || conns["mydb"].URL != "mysql://10.0.0.20:3306/app" {
			t.Errorf("mydb %+v %+v", conns["mydb"], c)
		}
	})
	t.Run("a VPN config file and an outside store login", func(t *testing.T) {
		v := vpns["ovpn"]
		if v.ConfigCredential != "ovpn-config" || creds["ovpn-config"].Kind != CredToken || v.User != "me" {
			t.Errorf("ovpn %+v", v)
		}
		c := creds[v.Credential]
		if c == nil || c.Store != "onepassword" || c.Item != "Private/vpn/password" || c.Kind != CredPassword || c.Value != nil {
			t.Errorf("ovpn credential %q %+v", v.Credential, c)
		}
		h := creds[hosts["vh"].Credential]
		if h == nil || h.Store != "vault" || h.Item != "kv/app#pw" || h.User != "root" {
			t.Errorf("vh %q %+v", hosts["vh"].Credential, h)
		}
		stores := byName[CredentialStore](t, res.readBack, KindCredStore)
		for _, p := range []string{"env", "vault", "onepassword"} {
			if s := stores[p]; s == nil || s.Provider != p {
				t.Errorf("store %s: %+v", p, s)
			}
		}
	})
	t.Run("runtime.json is gone after the migration", func(t *testing.T) {
		if _, err := os.Stat(runtimePath()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("runtime.json: %v", err)
		}
	})
	t.Run("report", func(t *testing.T) {
		r := res.report
		if !slices.Contains(r.SnippetsWithOldRef, "r1") {
			t.Errorf("snippets %v", r.SnippetsWithOldRef)
		}
		if !slices.ContainsFunc(r.Names, func(n nameChange) bool {
			return n.Old == "deploy" && slices.Equal(n.New, []string{"deploy-app", "deploy-root"})
		}) {
			t.Errorf("names %+v", r.Names)
		}
		fi, err := os.Stat(r.Backup)
		if err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 { // Windows has no mode bits
			t.Errorf("backup %s: %v", r.Backup, err)
		}
		if r.Counts[KindCredential][1] != len(creds) {
			t.Errorf("counts %v", r.Counts)
		}
	})
	t.Run("no value in the report, the notices or the audit entry", func(t *testing.T) {
		b, _ := json.Marshal(res.report)
		for what, s := range map[string]string{"report": string(b), "notices": said.String(), "audit": res.auditEntry} {
			if strings.Contains(s, sentinel) {
				t.Errorf("the %s holds a secret value", what)
			}
		}
	})
	t.Run("an older komando cannot open it", func(t *testing.T) {
		Close()
		if _, err := DB(false); !errors.Is(err, sealdb.ErrNewerFormat) {
			t.Error("the format-2 code opened a format-3 store")
		}
	})
}

func countType(recs []record3, typ string) int {
	n := 0
	for _, r := range recs {
		if r.typ == typ {
			n++
		}
	}
	return n
}

// Every stop leaves the file as it was, names what stopped it, and holds no
// value.
func TestMigrate3FailsClosed(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T)
		opts  func(o *migrate3Opts)
		code  string
	}{
		{name: "an AI agent or a script", opts: func(o *migrate3Opts) { o.person = false }, code: "NEEDS_PERSON"},
		{
			name: "a komando process still runs",
			setup: func(t *testing.T) {
				err := UpdateRuntime(Save(), func(s *State) error {
					s.Sessions["wg"] = &VpnSession{Vpn: "wg", PID: 4242, ProcStart: "x"}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			},
			opts: func(o *migrate3Opts) { o.alive = func(pid int, _ string) bool { return pid == 4242 } },
			code: "STORE_IN_USE",
		},
		{
			name: "a deny pattern changed outside komando",
			setup: func(t *testing.T) {
				rowKeyOnly(t, func(tx *sealdb.Tx) error {
					rs, err := tx.List(kindSettings)
					if err != nil || len(rs) != 1 {
						return errors.Join(err, errors.New("no settings record"))
					}
					data := bytes.Replace(rs[0].Data, []byte("rm -rf /srv"), []byte("rm -rf /tmp"), 1)
					_, err = tx.Put(kindSettings, rs[0].ID, data)
					return err
				})
			},
			code: "POLICY_MAC_FAILED",
		},
		{
			name: "a broken audit chain",
			setup: func(t *testing.T) {
				Close()
				raw := rawSQL(t)
				if _, err := raw.Exec(`DELETE FROM audit WHERE seq=1`); err != nil {
					t.Fatal(err)
				}
			},
			code: "NEEDS_PERSON",
		},
		{
			name: "a conn of a kind with no provider",
			setup: func(t *testing.T) {
				err := Update(Save(), func(s *State) error {
					s.Conns["odd"] = &Conn{Name: "odd", Kind: "gopher", URL: "gopher://h"}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			},
			code: "STORE_MIGRATION_FAILED",
		},
		{
			name: "a reference to a secret that is gone",
			setup: func(t *testing.T) {
				err := Update(Save(), func(s *State) error {
					s.Hosts["lost"] = &Host{Name: "lost", Address: "10.0.1.1", PasswordRef: "secret:nobody"}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			},
			code: "STORE_MIGRATION_FAILED",
		},
		{
			name: "a file item the reference guard refuses",
			setup: func(t *testing.T) {
				err := Update(Save(), func(s *State) error {
					s.Hosts["sneaky"] = &Host{Name: "sneaky", Address: "10.0.1.2", PasswordRef: "file:" + Path("store.key")}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			},
			opts: func(o *migrate3Opts) {
				o.refGuard = func(kind, name string) error {
					if kind == "file" && strings.HasPrefix(name, Home()) {
						return errors.New("a file of komando's home")
					}
					return nil
				}
			},
			code: "STORE_MIGRATION_FAILED",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format2Store(t)
			if tt.setup != nil {
				tt.setup(t)
			}
			Close()
			before := fileSum(t)
			said := notices(t)
			o := personOpts()
			if tt.opts != nil {
				tt.opts(&o)
			}
			_, err := migrateFormat3(context.Background(), o)
			var e *out.Error
			if !errors.As(err, &e) || e.Code != tt.code {
				t.Fatalf("want %s, got %v", tt.code, err)
			}
			if want := map[string]int{"STORE_IN_USE": out.ExitConflict, "STORE_MIGRATION_FAILED": out.ExitError, "NEEDS_PERSON": out.ExitPolicy}[tt.code]; want != 0 && e.Exit != want {
				t.Errorf("%s: exit %d, want %d (S-8.2)", tt.code, e.Exit, want)
			}
			Close()
			if f := formatNow(t); f != "2" {
				t.Errorf("format %s after a stop", f)
			}
			if fileSum(t) != before {
				t.Error("the store file changed")
			}
			for what, s := range map[string]string{"error": e.Message + e.Hint, "notices": said.String()} {
				if strings.Contains(s, sentinel) {
					t.Errorf("the %s holds a secret value", what)
				}
			}
		})
	}
}

// rowKeyOnly changes the store as a process with only the row key would:
// past the policy MAC.
func rowKeyOnly(t *testing.T, fn func(tx *sealdb.Tx) error) {
	t.Helper()
	Close()
	master, _, err := KeySource(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keysFor(master, "2")
	if err != nil {
		t.Fatal(err)
	}
	d, err := sealdb.Open(context.Background(), DBPath(), ks.row)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Update(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

// A store already at format 3 is left alone.
func TestMigrate3Twice(t *testing.T) {
	format2Store(t)
	if _, err := migrateFormat3(context.Background(), personOpts()); err != nil {
		t.Fatal(err)
	}
	Close()
	before := fileSum(t)
	res, err := migrateFormat3(context.Background(), personOpts())
	if err != nil || res.report.Backup != "" {
		t.Fatalf("a second run: %v %+v", err, res.report)
	}
	if fileSum(t) != before {
		t.Error("a second run changed the store")
	}
}

// The backup opens with the old key and holds what the store held.
func TestMigrate3Backup(t *testing.T) {
	format2Store(t)
	res, err := migrateFormat3(context.Background(), personOpts())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(res.report.Backup) != Home() || !strings.HasPrefix(filepath.Base(res.report.Backup), "store-v0-17-backup-") {
		t.Errorf("backup %s", res.report.Backup)
	}
	master, _, err := KeySource(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keysFor(master, "2")
	if err != nil {
		t.Fatal(err)
	}
	b, err := sealdb.Open(context.Background(), res.report.Backup, ks.row)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	err = b.View(context.Background(), func(tx *sealdb.Tx) error {
		rs, err := tx.List("secret")
		if err == nil && len(rs) != len(testSecrets) {
			err = errors.New("the backup lost secrets")
		}
		return err
	})
	if err != nil {
		t.Error(err)
	}
}

// rawSQL opens store.db past sealdb, as something other than komando would.
func rawSQL(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+DBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// A second backup in the same second takes -2: a backup is never
// overwritten, so a run after a stopped one still makes its own.
func TestMigrate3BackupNameTaken(t *testing.T) {
	format2Store(t)
	now := time.Date(2026, 11, 24, 9, 30, 0, 0, time.UTC)
	first := Path("store-v0-17-backup-2026-11-24-093000.db")
	if err := os.WriteFile(first, []byte("an earlier backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := personOpts()
	o.now = func() time.Time { return now }
	res, err := migrateFormat3(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.report.Backup != Path("store-v0-17-backup-2026-11-24-093000-2.db") {
		t.Errorf("backup %s", res.report.Backup)
	}
	if b, _ := os.ReadFile(first); string(b) != "an earlier backup" {
		t.Error("the earlier backup was overwritten")
	}
}

// R1: a migration with no way to see processes stops; it never guesses
// that nothing runs.
func TestNoLiveProcessesNeedsCheck(t *testing.T) {
	sealedHome(t)
	if err := noLiveProcesses(nil); err == nil {
		t.Fatal("no process check given, and the migration went on")
	}
}

// R2: a password written into a conn URL's user part stops the plan, which
// names the conn and the field and not the password.
func TestMigrate3PasswordInURL(t *testing.T) {
	format2Store(t)
	err := Update(Save(), func(s *State) error {
		s.Conns["inline"] = &Conn{Name: "inline", Kind: "postgres", URL: "postgres://app:" + sentinel + "@10.0.0.30/app"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	Close()
	_, err = migrateFormat3(context.Background(), personOpts())
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "STORE_MIGRATION_FAILED" {
		t.Fatalf("want STORE_MIGRATION_FAILED, got %v", err)
	}
	if !strings.Contains(e.Message, "conn inline") || !strings.Contains(e.Message, "field url") || strings.Contains(e.Message, sentinel) {
		t.Errorf("message %q", e.Message)
	}
}

// T2: a broken audit chain is a person's to look into (exit 6), and the
// hint says so.
func TestMigrate3BrokenChainHint(t *testing.T) {
	format2Store(t)
	Close()
	if _, err := rawSQL(t).Exec(`DELETE FROM audit WHERE seq=1`); err != nil {
		t.Fatal(err)
	}
	_, err := migrateFormat3(context.Background(), personOpts())
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "NEEDS_PERSON" || e.Exit != out.ExitPolicy {
		t.Fatalf("want NEEDS_PERSON (exit 6), got %v", err)
	}
	if !strings.Contains(e.Message, "audit log") || !strings.Contains(e.Hint, "changed the audit log") {
		t.Errorf("message %q, hint %q", e.Message, e.Hint)
	}
}

// T1: a conn URL that does not parse stops the plan, naming the conn and
// the field and not the URL.
func TestMigrate3UnparsableURL(t *testing.T) {
	format2Store(t)
	err := Update(Save(), func(s *State) error {
		s.Conns["bent"] = &Conn{Name: "bent", Kind: "postgres", URL: "postgres://app@10.0.0.31/%zz" + sentinel}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	Close()
	_, err = migrateFormat3(context.Background(), personOpts())
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "STORE_MIGRATION_FAILED" {
		t.Fatalf("want STORE_MIGRATION_FAILED, got %v", err)
	}
	if !strings.Contains(e.Message, "conn bent") || !strings.Contains(e.Message, "field url") || strings.Contains(e.Message, sentinel) {
		t.Errorf("message %q", e.Message)
	}
}
