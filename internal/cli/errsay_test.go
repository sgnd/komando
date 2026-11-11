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
	c, _, err := newRoot().Find(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNotFoundSayScopedWithNearMatch(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	e := out.Errf(out.ExitNotFound, "HOST_NOT_FOUND", "h", "host %q not found", "wbe1")
	notFoundSay(e, sayCmd(t, "exec"))
	if got := e.TextMessage(); got != `No server named "wbe1". Did you mean web1?` {
		t.Errorf("message: %q", got)
	}
	if !strings.Contains(e.TextHint(), "Your servers: web1.") {
		t.Errorf("hint: %q", e.TextHint())
	}
	if e.Message != `host "wbe1" not found` {
		t.Errorf("JSON message changed: %q", e.Message)
	}
	e = out.Errf(out.ExitNotFound, "CONN_NOT_FOUND", "h", "target %q picked no conns", "nosuch")
	notFoundSay(e, sayCmd(t, "db", "query"))
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
		code, msg string
		say, hint string
	}{
		{[]string{"conn", "edit"}, "CONN_NOT_FOUND", `conn "web1" not found`,
			"web1 is a server, not a conn.", "Use `komando host edit web1`."},
		{[]string{"host", "rm"}, "HOST_NOT_FOUND", `host "pg2" not found`,
			"pg2 is a postgres conn, not a server.", "Use `komando conn rm pg2`."},
		{[]string{"exec"}, "HOST_NOT_FOUND", `host "pg2" not found`,
			"pg2 is a postgres conn, not a server.", "Use it with `komando db`."},
		{[]string{"list"}, "TARGET_NOT_FOUND", `no server, conn or VPN named "pgg"`,
			`No server, conn or VPN named "pgg". Did you mean pg2?`, "Your servers, conns and VPNs: pg2, web1."},
		{[]string{"vpn", "list"}, "TARGET_NOT_FOUND", `no server, conn or VPN named "nosuch"`,
			`No VPN named "nosuch".`, "You have no VPN yet: add one with `komando vpn add NAME KIND`"},
	} {
		e := out.Errf(out.ExitNotFound, c.code, "h", "%s", c.msg)
		notFoundSay(e, sayCmd(t, c.path...))
		if e.TextMessage() != c.say || !strings.HasPrefix(e.TextHint(), c.hint) {
			t.Errorf("%v: %q / %q", c.path, e.TextMessage(), e.TextHint())
		}
	}
}

// An agent or script cannot use the menu, so the hint is a command line;
// a command's own words for a person (cert check's website tip) stay.
func TestNotFoundSayNoMenuForScripts(t *testing.T) {
	invHome(t)
	e := out.Errf(out.ExitNotFound, "HOST_NOT_FOUND", "h", "host %q not found", "bastion")
	notFoundSay(e, sayCmd(t, "host", "show"))
	if h := e.TextHint(); strings.Contains(h, "pick Add") || !strings.Contains(h, "komando host add NAME user@address") {
		t.Errorf("hint: %q", h)
	}
	e = out.Errf(out.ExitNotFound, "TARGET_NOT_FOUND", "for a website write https://shop.example.com", "no server, conn or VPN named %q", "shop.example.com")
	e.Say("Nothing named \"shop.example.com\" in your list to check.", e.Hint)
	notFoundSay(e, sayCmd(t, "cert", "check"))
	if !strings.Contains(e.TextHint(), "https://shop.example.com") {
		t.Errorf("cert hint lost: %q", e.TextHint())
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
	saved := askedAbout
	defer func() { askedAbout = saved }()
	askedAbout = names
	return cancelledText()
}
