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
		return targetTest{Name: name, Kind: "host", Error: &out.Error{Code: "NO_AUTH", Message: "no login", Hint: "run komando login " + name}}
	}
	if s := (testData{Results: []targetTest{fail("local1")}}).Text(); strings.Contains(s, "komando login") {
		t.Errorf("one target:\n%s", s)
	}
	if s := (testData{Results: []targetTest{fail("a"), fail("b")}}).Text(); strings.Count(s, "komando login") != 2 {
		t.Errorf("two targets:\n%s", s)
	}
}
