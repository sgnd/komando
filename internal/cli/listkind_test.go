package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// `host list appdb` for a conn is NO_MATCHING_TARGETS, as `host test
// appdb` is: a selector that picks nothing never succeeds with no rows.
func TestKindListPicksNothing(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	mustRun(t, "conn", "add", "appdb", "postgres://u@127.0.0.1:5/db")
	for _, args := range [][]string{{"host", "list", "appdb"}, {"conn", "list", "web1"}, {"vpn", "list", "web1"}} {
		if e := wantCode(t, "NO_MATCHING_TARGETS", args...); e.Exit != 3 {
			t.Errorf("%v: exit %d", args, e.Exit)
		}
	}
	if d := mustRun(t, "host", "ls", "web1"); d["count"] != float64(1) {
		t.Errorf("host ls web1: %v", d)
	}
	if d := mustRun(t, "host", "list"); d["count"] != float64(1) {
		t.Errorf("host list: %v", d)
	}
}

func TestVpnWhereShowsPortal(t *testing.T) {
	if w := vpnWhere(&store.Vpn{Kind: "globalprotect", Portal: "vpn.example.com"}); w != "vpn.example.com" {
		t.Errorf("got %q", w)
	}
}

// One failed target: its hint comes once, with the error; several keep a
// hint under each row.
func TestTestTextHintOnce(t *testing.T) {
	fail := func(name string) targetTest {
		return targetTest{Host: name, Kind: "host", Error: &out.Error{Code: "NO_AUTH", Message: "no login", Hint: "run komando login " + name}}
	}
	if s := (testData{Results: []targetTest{fail("local1")}}).Text(); strings.Contains(s, "komando login") {
		t.Errorf("one target:\n%s", s)
	}
	if s := (testData{Results: []targetTest{fail("a"), fail("b")}}).Text(); strings.Count(s, "komando login") != 2 {
		t.Errorf("two targets:\n%s", s)
	}
}

// A change says what happened first, in words, not a dump of fields.
func TestChangeSay(t *testing.T) {
	for _, c := range []struct {
		dry                    bool
		verb, what, where, say string
	}{
		{false, "add", "web1 and web2", "to @web", "added web1 and web2 to @web"},
		{true, "add", "web1", "to @web", "would add web1 to @web (dry run)"},
		{false, "add", "", "to @web", "nothing to add"},
		{false, "remove", "recipe up", "", "removed recipe up"},
		{false, "save", "recipe up", "", "saved recipe up"},
	} {
		g.dryRun = c.dry
		if got := changeSay(c.verb, c.what, c.where); got != c.say {
			t.Errorf("got %q, want %q", got, c.say)
		}
	}
	g.dryRun = false
}

// The error says what the selector did pick, as other commands do.
func TestKindListSaysWhatItPicked(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	if e := wantCode(t, "NO_MATCHING_TARGETS", "vpn", "list", "web1"); e.Message != `target "web1" picked no VPNs, only: web1 (server)` {
		t.Errorf("vpn list: %q", e.Message)
	}
	if e := wantCode(t, "NO_MATCHING_TARGETS", "conn", "test", "web1"); e.Message != `target "web1" picked no conns, only: web1 (server)` {
		t.Errorf("conn test: %q", e.Message)
	}
}
