package store

import (
	"slices"
	"testing"
)

// swarmsOf is every swarm service of s by its manager's record ID.
func swarmsOf(s *State) map[string][]*Conn {
	m := map[string][]*Conn{}
	for _, c := range s.Conns {
		if c.Kind == "swarm" {
			m[c.ManagerID] = append(m[c.ManagerID], c)
		}
	}
	return m
}

// Removed by the C cluster row: until it gives a swarm its own add path,
// a host saved with the swarm tag becomes a swarm service whose manager is
// that host, as the migration makes it; the host keeps no swarm tag.
func TestFormat3SwarmTagBecomesService(t *testing.T) {
	sealedHome(t)
	fakeKeys(t)
	if err := Update(Save(), func(s *State) error {
		s.Conns["web1-swarm"] = &Conn{Name: "web1-swarm", Kind: "postgres", URL: "postgres://u@h/d"}
		s.Hosts["web1"] = &Host{Name: "web1", Address: "10.0.0.1", Tags: []string{"swarm", "edge"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	h := s.Hosts["web1"]
	if slices.Contains(h.Tags, "swarm") || !slices.Contains(h.Tags, "edge") {
		t.Fatalf("host tags %v", h.Tags)
	}
	sw := swarmsOf(s)[h.Rec.ID]
	if len(sw) != 1 || sw[0].Manager != "web1" || sw[0].Name != "web1-swarm-2" {
		t.Fatalf("swarm services %+v", sw)
	}
	// the tag again on the same host makes no second service
	if err := Update(Save(), func(s *State) error {
		s.Hosts["web1"].Tags = append(s.Hosts["web1"].Tags, "swarm")
		s.Hosts["web1"].Notes = "again"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if s, err = Load(); err != nil {
		t.Fatal(err)
	}
	if sw := swarmsOf(s)[h.Rec.ID]; len(sw) != 1 || slices.Contains(s.Hosts["web1"].Tags, "swarm") {
		t.Fatalf("second save: services %+v, tags %v", sw, s.Hosts["web1"].Tags)
	}
}
