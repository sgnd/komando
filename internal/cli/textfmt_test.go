package cli

import (
	"testing"
	"time"
)

func TestTextTable(t *testing.T) {
	got := textTable([]string{"name", "state"}, [][]string{{"web-1", "running"}, {"db", ""}})
	want := "NAME   STATE\nweb-1  running\ndb     -\n"
	if got != want {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
	if humanAge(40*time.Second) != "40s" || humanAge(3*time.Hour) != "3h" || humanAge(72*time.Hour) != "3d" {
		t.Error("humanAge")
	}
}

func TestSameHostName(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{{"target", "TARGET", true}, {"db.example", "db.example.", true}, {"[::1]", "::1", true}, {"a", "b", false}} {
		if sameHostName(c.a, c.b) != c.same {
			t.Errorf("sameHostName(%q, %q) != %v", c.a, c.b, c.same)
		}
	}
	if normHostPort("Maria.:3306") != "maria:3306" {
		t.Error(normHostPort("Maria.:3306"))
	}
}
