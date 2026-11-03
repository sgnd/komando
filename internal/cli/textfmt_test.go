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
