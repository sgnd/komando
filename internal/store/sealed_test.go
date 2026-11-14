package store

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/sealrow"

	"github.com/sgnd/komando/internal/sealdb"
)

func sealedStore(t *testing.T) string {
	t.Helper()
	home := sealedHome(t)
	fakeKeys(t)
	return home
}

func TestSealedRoundTrip(t *testing.T) {
	home := sealedStore(t)
	if s, err := Load(); err != nil || len(s.Hosts) != 0 {
		t.Fatalf("empty: %v", err)
	}
	if _, err := os.Stat(Path(StoreFile)); !os.IsNotExist(err) {
		t.Fatal("a read made the store")
	}
	update(t, func(s *State) {
		s.Hosts["web"] = &Host{Name: "web", Address: "prod-web.example.com", Protected: true}
		s.Conns["db"] = &Conn{Name: "db", Kind: "postgres", URL: "postgres://x"}
		s.Vpns["office"] = &Vpn{Name: "office", Kind: "socks"}
		s.Keys["k"] = &Key{Name: "k", Path: "/x"}
		s.Snippets["up"] = &Snippet{Name: "up", Command: "uptime"}
		s.Settings.HostKeyPolicy = "strict"
		s.Settings.ExtraDenyPattern = []string{"rm -rf /srv"}
		s.Jobs["j"] = &Job{ID: "j"}
	})
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if h := s.Hosts["web"]; h == nil || !h.Protected || h.Rec.ID == "" || h.Rec.Version != 1 {
		t.Fatalf("host %+v", h)
	}
	if s.Conns["db"] == nil || s.Vpns["office"] == nil || s.Keys["k"] == nil || s.Snippets["up"] == nil {
		t.Fatal("a record kind was lost")
	}
	if s.Settings.HostKeyPolicy != "strict" || len(s.Settings.ExtraDenyPattern) != 1 || s.Settings.Parallel == 0 {
		t.Fatalf("settings %+v", s.Settings)
	}
	if s.Jobs["j"] == nil {
		t.Fatal("runtime lost")
	}
	// nothing readable on disk, and no state.json
	for _, f := range []string{"state.json", "vault.json"} {
		if _, err := os.Stat(filepath.Join(home, f)); !os.IsNotExist(err) {
			t.Fatalf("%s written in a sealed home", f)
		}
	}
	b, _ := os.ReadFile(Path(StoreFile))
	for _, w := range []string{"prod-web", "rm -rf", "uptime", "strict"} {
		if strings.Contains(string(b), w) {
			t.Fatalf("%q readable in store.db", w)
		}
	}
}

func TestSealedVersionsAndDeletes(t *testing.T) {
	sealedStore(t)
	update(t, func(s *State) {
		s.Hosts["a"] = &Host{Name: "a"}
		s.Hosts["b"] = &Host{Name: "b"}
	})
	a := recOf(t, KindHost, "a")
	update(t, func(s *State) { s.Hosts["b"].Address = "x" })
	if recOf(t, KindHost, "a") != a {
		t.Fatal("an unchanged record was written")
	}
	b := recOf(t, KindHost, "b")
	if b.Version != 2 {
		t.Fatalf("b %+v", b)
	}
	update(t, func(s *State) {
		h := s.Hosts["a"]
		delete(s.Hosts, "a")
		h.Name = "a2"
		s.Hosts["a2"] = h
	})
	if r := recOf(t, KindHost, "a2"); r.ID != a.ID || r.Version != 2 {
		t.Fatalf("rename %+v", r)
	}
	update(t, func(s *State) { delete(s.Hosts, "b") })
	d, _ := DB(false)
	_ = d.View(context.Background(), func(tx *sealdb.Tx) error {
		r, err := tx.Get(b.ID)
		if err != nil || !r.Deleted {
			t.Fatalf("deleted host: %+v %v", r, err)
		}
		return nil
	})
	if s, _ := Load(); len(s.Hosts) != 1 {
		t.Fatalf("hosts %v", s.Hosts)
	}
	// a fn error writes nothing
	err := Update(Save(), func(s *State) error {
		s.Hosts["z"] = &Host{Name: "z"}
		return os.ErrInvalid
	})
	if err == nil {
		t.Fatal("error lost")
	}
	if s, _ := Load(); s.Hosts["z"] != nil {
		t.Fatal("a failed change was saved")
	}
}

func TestSealedRuntimeOnly(t *testing.T) {
	sealedStore(t)
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	if err := UpdateRuntime(Save(), func(s *State) error { s.Jobs["j"] = &Job{ID: "j"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := UpdateRuntime(Save(), func(s *State) error { s.Hosts["a"].User = "x"; return nil }); err != ErrRuntimeOnly {
		t.Fatalf("%v", err)
	}
	if s, _ := Load(); s.Jobs["j"] == nil || s.Hosts["a"].User != "" {
		t.Fatal("runtime-only rules broken in a sealed home")
	}
}

// TestSealedAcrossProcesses: several processes add hosts and all try one
// shared name inside one write step each; every host lands once.
func TestSealedAcrossProcesses(t *testing.T) {
	if home := os.Getenv("STORE_CHILD_HOME"); home != "" {
		t.Setenv("KOMANDO_HOME", home)
		t.Cleanup(Close) // before the folder goes: Windows cannot remove an open file
		fakeKeys(t)
		n := os.Getenv("STORE_CHILD_N")
		for i := range 10 {
			name := "h" + n + "-" + strconv.Itoa(i)
			if err := Update(Save(), func(s *State) error {
				s.Hosts[name] = &Host{Name: name}
				if _, ok := s.Hosts["shared"]; !ok {
					s.Hosts["shared"] = &Host{Name: "shared", User: n}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	home := sealedStore(t)
	update(t, func(*State) {})
	var cmds []*exec.Cmd
	for i := range 4 {
		c := exec.Command(os.Args[0], "-test.run=^TestSealedAcrossProcesses$", "-test.count=1")
		c.Env = append(os.Environ(), "STORE_CHILD_HOME="+home, "STORE_CHILD_N="+strconv.Itoa(i))
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, c)
	}
	for _, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	Close()
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Hosts) != 41 {
		t.Fatalf("%d hosts, want 41", len(s.Hosts))
	}
}

// On a sealed home runtime.json is sealed: the SOCKS login of a running
// VPN cannot be read from it, a plain one is read as empty, and the
// prompt's reader opens it.
func TestSealedRuntimeFile(t *testing.T) {
	sealedStore(t)
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	if err := UpdateRuntime(Save(), func(s *State) error {
		s.Sessions["office"] = &VpnSession{Vpn: "office", PID: 7, SocksPass: "socks-s3cret"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(runtimePath())
	if !strings.HasPrefix(string(b), string(runtimeMagic)) || strings.Contains(string(b), "socks-s3cret") || strings.Contains(string(b), "office") {
		t.Fatalf("runtime.json not sealed: %q", b)
	}
	if s, err := Load(); err != nil || s.Sessions["office"].SocksPass != "socks-s3cret" {
		t.Fatalf("load: %v", err)
	}
	if rt, err := ReadRuntime(); err != nil || rt.Sessions["office"] == nil {
		t.Fatalf("ReadRuntime: %v", err)
	}
	// a plain file was not written by komando: read as empty
	if err := os.WriteFile(runtimePath(), []byte(`{"jobs":{"j":{"id":"j"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := Load(); err != nil || s.Jobs["j"] != nil {
		t.Fatalf("a plain runtime.json was trusted: %v", err)
	}
	// a damaged sealed file is refused, not read as empty
	if err := os.WriteFile(runtimePath(), append(append([]byte{}, runtimeMagic...), "junk"...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("a damaged sealed runtime.json was accepted")
	}
}

// A plain runtime.json put beside a sealed store is never trusted: it could
// point a server's held login at a socket that is not komando's, which
// would then see every command, password and file sent to that server.
func TestForgedPlainRuntimeIgnored(t *testing.T) {
	sealedStore(t)
	update(t, func(s *State) { s.Hosts["prod"] = &Host{Name: "prod", Address: "10.0.0.1", User: "root"} })
	forged := `{"ssh_logins":{"prod":{"host":"prod","target":"x","socket":"/tmp/evil.sock","token":"t","host_key":"k","until":"2099-01-01T00:00:00Z"}},` +
		`"vpn_sessions":{"office":{"vpn":"office","pid":1,"socks":"127.0.0.1:9"}}}`
	if err := os.WriteFile(runtimePath(), []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Logins["prod"] != nil || s.Sessions["office"] != nil {
		t.Fatalf("a forged plain runtime.json was trusted: %+v %+v", s.Logins["prod"], s.Sessions["office"])
	}
	if rt, err := ReadRuntime(); err != nil || len(rt.Logins)+len(rt.Sessions) != 0 {
		t.Fatalf("ReadRuntime trusted it: %v", err)
	}
	// the next runtime write seals over it
	if err := UpdateRuntime(Save(), func(s *State) error { s.Jobs["k"] = &Job{ID: "k"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(runtimePath()); !strings.HasPrefix(string(b), string(runtimeMagic)) || strings.Contains(string(b), "evil") {
		t.Fatalf("not sealed over: %q", b)
	}
}

// A runtime change on a fresh sealed home (a VPN before any server) makes
// the store, so runtime.json is never plain there.
func TestSealedRuntimeBeforeStore(t *testing.T) {
	sealedStore(t)
	if err := UpdateRuntime(Save(), func(s *State) error { s.Jobs["j"] = &Job{ID: "j", Command: "secret-cmd"}; return nil }); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(runtimePath())
	if strings.Contains(string(b), "secret-cmd") {
		t.Fatal("runtime.json written plain before the store existed")
	}
}

// runtime.pids beside a sealed runtime.json holds only processes: no
// names, logins or tokens, and it opens without the key.
func TestSealedRuntimePIDs(t *testing.T) {
	sealedStore(t)
	if err := UpdateRuntime(Save(), func(s *State) error {
		s.Sessions["office-vpn"] = &VpnSession{Vpn: "office-vpn", PID: 4242, SocksPass: "pw"}
		s.Tunnels["t"] = &Tunnel{ID: "t", Host: "db-host", PID: 4343}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(Path("runtime.pids"))
	for _, w := range []string{"office", "db-host", "pw"} {
		if strings.Contains(string(b), w) {
			t.Fatalf("runtime.pids holds %q: %s", w, b)
		}
	}
	p, err := ReadRuntimePIDs()
	if err != nil || len(p.Vpns) != 1 || p.Vpns[0].PID != 4242 || len(p.Tunnels) != 1 || p.Tunnels[0] != 4343 {
		t.Fatalf("pids %+v %v", p, err)
	}
}

// A runtime.json sealed with another key stops with STATE_CORRUPT and a
// way out, not a bare error.
func TestSealedRuntimeWrongKey(t *testing.T) {
	sealedStore(t)
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	other, _ := sealrow.NewKey(bytes.Repeat([]byte{9}, 32))
	sealed, _ := other.Seal(runtimeRow, []byte(`{}`))
	if err := os.WriteFile(runtimePath(), append(append([]byte{}, runtimeMagic...), sealed...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("err %v", err)
	}
}
