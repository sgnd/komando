package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// sayCmd is the command named by path, as Execute hands it to notFoundSay.
func sayCmd(t *testing.T, path ...string) *cobra.Command {
	t.Helper()
	c, _, err := newRoot(tcl).Find(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNotFoundSayScopedWithNearMatch(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	e := out.Errf(out.ExitNotFound, "TARGET_NOT_FOUND", "h", "host %q not found", "wbe1").ForKind("host")
	notFoundSay(tcl, e, sayCmd(t, "exec"))
	if got := e.TextMessage(); got != `No server named "wbe1". Did you mean web1?` {
		t.Errorf("message: %q", got)
	}
	if !strings.Contains(e.TextHint(), "Your servers: web1.") {
		t.Errorf("hint: %q", e.TextHint())
	}
	if e.Message != `host "wbe1" not found` {
		t.Errorf("JSON message changed: %q", e.Message)
	}
	e = out.Errf(out.ExitNotFound, "TARGET_NOT_FOUND", "h", "target %q picked no conns", "nosuch").ForKind("conn")
	notFoundSay(tcl, e, sayCmd(t, "db", "query"))
	if e.TextMessage() != `No database named "nosuch".` || !strings.Contains(e.TextHint(), "no database yet") {
		t.Errorf("no databases: %q / %q", e.TextMessage(), e.TextHint())
	}
}

// A name of another kind is named as such, never offered back as "did you
// mean" itself; a lookup of every kind suggests from every kind.
func TestNotFoundSayOtherKind(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	mustRun(t, "conn", "add", "pg2", "postgres://u@127.0.0.1:5/db")
	for _, c := range []struct {
		path      []string
		kind, msg string
		say, hint string
	}{
		{[]string{"conn", "edit"}, "conn", `conn "web1" not found`,
			"web1 is a server, not a conn.", "Use `komando host edit web1`."},
		{[]string{"host", "rm"}, "host", `host "pg2" not found`,
			"pg2 is a postgres conn, not a server.", "Use `komando conn rm pg2`."},
		{[]string{"exec"}, "host", `host "pg2" not found`,
			"pg2 is a postgres conn, not a server.", "Use it with `komando db`."},
		{[]string{"list"}, "", `no server, conn or VPN named "pgg"`,
			`No server, conn or VPN named "pgg". Did you mean pg2?`, "Your servers, conns and VPNs: pg2, web1."},
		{[]string{"vpn", "list"}, "", `no server, conn or VPN named "nosuch"`,
			`No VPN named "nosuch".`, "You have no VPN yet: add one with `komando vpn add NAME KIND`"},
	} {
		e := out.Errf(out.ExitNotFound, "TARGET_NOT_FOUND", "h", "%s", c.msg).ForKind(c.kind)
		notFoundSay(tcl, e, sayCmd(t, c.path...))
		if e.TextMessage() != c.say || !strings.HasPrefix(e.TextHint(), c.hint) {
			t.Errorf("%v: %q / %q", c.path, e.TextMessage(), e.TextHint())
		}
	}
}

// An agent or script cannot use the menu, so the hint is a command line.
func TestNotFoundSayNoMenuForScripts(t *testing.T) {
	invHome(t)
	e := out.Errf(out.ExitNotFound, "TARGET_NOT_FOUND", "h", "host %q not found", "bastion").ForKind("host")
	notFoundSay(tcl, e, sayCmd(t, "host", "show"))
	if h := e.TextHint(); strings.Contains(h, "pick Add") || !strings.Contains(h, "komando host add NAME user@address") {
		t.Errorf("hint: %q", h)
	}
	// a person at a terminal gets the add command to type alone (it asks
	// step by step): there is no menu to pick Add in
	saved := tcl.terminal
	tcl.terminal = true
	t.Cleanup(func() { tcl.terminal = saved })
	for _, c := range [][2]string{{"host", "`komando host add`"}, {"conn", "`komando conn add`"}, {"vpn", "`komando vpn add`"}} {
		e = out.Errf(out.ExitNotFound, "TARGET_NOT_FOUND", "h", "%q not found", "nosuch").ForKind(c[0])
		cmd := map[string][]string{"host": {"host", "show"}, "conn": {"conn", "show"}, "vpn": {"vpn", "up"}}[c[0]]
		notFoundSay(tcl, e, sayCmd(t, cmd...))
		if h := e.TextHint(); strings.Contains(h, "pick Add") || strings.Contains(h, "menu") || !strings.Contains(h, c[1]) {
			t.Errorf("%s at a terminal: %q", c[0], h)
		}
	}
}

func TestProtectedSayNamesTheKind(t *testing.T) {
	conns := []*store.Conn{{Name: "db-main", Kind: "postgres"}}
	if got := protectedSay([]string{"db-main"}, connWord(conns, []string{"db-main"})); !strings.HasPrefix(got, "db-main is a protected database") {
		t.Errorf("got %q", got)
	}
	if got := cancelledTextFor([]string{"a", "b", "c"}); got != "Cancelled. Nothing was changed on a, b and c." {
		t.Errorf("got %q", got)
	}
}

func cancelledTextFor(names []string) string {
	saved := tcl.askedAbout
	defer func() { tcl.askedAbout = saved }()
	tcl.askedAbout = names
	return cancelledText(tcl)
}

// A hint written with a placeholder names the target the command was
// given, so the next step can be copied; `conn test` is spelled `test`.
func TestFillHint(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "pg", "postgres://u@127.0.0.1:5/db")
	e := out.Errf(out.ExitConnect, "DB_CONNECT", "run `komando conn test NAME` to check reachability", "x")
	fillHint(e, "pg")
	if e.Hint != "run `komando test pg` to check reachability" {
		t.Errorf("got %q", e.Hint)
	}
	e = out.Errf(out.ExitRemote, "TOOL_FAILED", "read stderr; `komando cluster events TARGET --warnings` shows more; `komando secret set NAME`", "x")
	fillHint(e, "pg")
	if e.Hint != "read stderr; `komando cluster events pg --warnings` shows more; `komando secret set NAME`" {
		t.Errorf("got %q", e.Hint)
	}
	// a VPN fills neither TARGET nor CONN, a server fills TARGET but not CONN
	mustRun(t, "vpn", "add", "corp", "socks", "--proxy-address", "127.0.0.1:1080")
	mustRun(t, "host", "add", "web1", "u@192.0.2.10")
	e = out.Errf(out.ExitConnect, "VPN_DOWN", "run `komando exec TARGET -- true` or `komando test NAME`", "x")
	fillHint(e, "corp")
	if e.Hint != "run `komando exec TARGET -- true` or `komando test corp`" {
		t.Errorf("vpn: got %q", e.Hint)
	}
	e = out.Errf(out.ExitConnect, "X", "`komando exec TARGET -- true`; `komando db query CONN \"select 1\"`", "x")
	fillHint(e, "web1")
	if e.Hint != "`komando exec web1 -- true`; `komando db query CONN \"select 1\"`" {
		t.Errorf("server: got %q", e.Hint)
	}
	// S-8.7: SERVER only with a server, NAME only in a command of the
	// target's own noun, CONN in `komando test CONN`
	e = out.Errf(out.ExitConnect, "X", "`komando fs stat SERVER ~/.ssh`; `komando host edit NAME --key K`; `komando conn edit NAME --via HOST`", "x")
	fillHint(e, "web1")
	if e.Hint != "`komando fs stat web1 ~/.ssh`; `komando host edit web1 --key K`; `komando conn edit NAME --via HOST`" {
		t.Errorf("server: got %q", e.Hint)
	}
	e = out.Errf(out.ExitConnect, "X", "`komando test CONN`; `komando fs stat SERVER ~/.ssh`; `komando conn edit NAME --via HOST`", "x")
	fillHint(e, "pg")
	if e.Hint != "`komando test pg`; `komando fs stat SERVER ~/.ssh`; `komando conn edit pg --via HOST`" {
		t.Errorf("conn: got %q", e.Hint)
	}
	e = out.Errf(out.ExitConnect, "DB_CONNECT", "run `komando conn test NAME`", "x")
	fillHint(e, "nosuch") // not a name komando knows: only the spelling changes
	if e.Hint != "run `komando test NAME`" {
		t.Errorf("got %q", e.Hint)
	}
}
