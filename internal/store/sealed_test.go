package store

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

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
	err := Update(func(s *State) error {
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
	if err := UpdateRuntime(func(s *State) error { s.Jobs["j"] = &Job{ID: "j"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := UpdateRuntime(func(s *State) error { s.Hosts["a"].User = "x"; return nil }); err != ErrRuntimeOnly {
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
		freshSealed = true
		fakeKeys(t)
		n := os.Getenv("STORE_CHILD_N")
		for i := range 10 {
			name := "h" + n + "-" + strconv.Itoa(i)
			if err := Update(func(s *State) error {
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
	closeDBs()
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Hosts) != 41 {
		t.Fatalf("%d hosts, want 41", len(s.Hosts))
	}
}
