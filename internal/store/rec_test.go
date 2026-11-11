package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func recOf(t *testing.T, kind, name string) Rec {
	t.Helper()
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range s.recs() {
		if r.kind == kind && r.name == name {
			return *r.rec
		}
	}
	t.Fatalf("no %s %s", kind, name)
	return Rec{}
}

func update(t *testing.T, fn func(s *State)) {
	t.Helper()
	if err := Update(func(s *State) error { fn(s); return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestRecIdentity(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	update(t, func(s *State) {
		s.Hosts["web"] = &Host{Name: "web", Address: "10.0.0.1"}
		s.Snippets["up"] = &Snippet{Name: "up", Command: "uptime"}
	})
	web := recOf(t, KindHost, "web")
	if len(web.ID) != 32 || web.Version != 1 {
		t.Fatalf("new host %+v", web)
	}
	if recOf(t, KindHost, "web") != web {
		t.Fatal("ID not stable across loads")
	}

	// a change to another record leaves this one alone
	update(t, func(s *State) { s.Snippets["up"].Command = "uptime -p" })
	if recOf(t, KindHost, "web") != web || recOf(t, KindRecipe, "up").Version != 2 {
		t.Fatal("wrong record bumped")
	}

	// a change bumps the version, keeps the ID
	update(t, func(s *State) { s.Hosts["web"].Address = "10.0.0.2" })
	if r := recOf(t, KindHost, "web"); r.ID != web.ID || r.Version != 2 {
		t.Fatalf("after edit %+v", r)
	}

	// a rename keeps the ID
	update(t, func(s *State) {
		h := s.Hosts["web"]
		delete(s.Hosts, "web")
		h.Name = "web1"
		s.Hosts["web1"] = h
	})
	if r := recOf(t, KindHost, "web1"); r.ID != web.ID || r.Version != 3 {
		t.Fatalf("after rename %+v", r)
	}

	// an overwrite with a fresh record takes the old ID
	update(t, func(s *State) { s.Hosts["web1"] = &Host{Name: "web1", Address: "10.0.0.3"} })
	if r := recOf(t, KindHost, "web1"); r.ID != web.ID || r.Version != 4 {
		t.Fatalf("after overwrite %+v", r)
	}

	// a copy of a record gets its own ID; the original keeps its
	update(t, func(s *State) {
		c := *s.Hosts["web1"]
		c.Name = "web2"
		s.Hosts["web2"] = &c
	})
	if r := recOf(t, KindHost, "web1"); r.ID != web.ID {
		t.Fatalf("original lost its ID: %+v", r)
	}
	if r := recOf(t, KindHost, "web2"); r.ID == web.ID || r.Version != 1 {
		t.Fatalf("copy %+v", r)
	}

	// a delete and a new record under the same name: a new record
	update(t, func(s *State) { delete(s.Snippets, "up") })
	update(t, func(s *State) { s.Snippets["up"] = &Snippet{Name: "up", Command: "w"} })
	if r := recOf(t, KindRecipe, "up"); r.Version != 1 {
		t.Fatalf("re-added recipe %+v", r)
	}
}

func TestRecNotInRecordJSON(t *testing.T) {
	b, _ := json.Marshal(&Host{Name: "a", Rec: Rec{ID: "x", Version: 3}})
	if strings.Contains(string(b), `"x"`) || strings.Contains(string(b), "version") {
		t.Fatalf("Rec leaks into the record: %s", b)
	}
}

func TestRecDryRun(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	a := recOf(t, KindHost, "a")
	DryRun = true
	defer func() { DryRun = false }()
	update(t, func(s *State) { s.Hosts["a"].Address = "x" })
	DryRun = false
	if recOf(t, KindHost, "a") != a {
		t.Fatal("dry run changed the record")
	}
}
