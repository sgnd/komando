package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

func TestNotFoundSayScopedWithNearMatch(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	e := out.Errf(out.ExitNotFound, "HOST_NOT_FOUND", "h", "host %q not found", "wbe1")
	notFoundSay(e, "exec")
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
	notFoundSay(e, "db")
	if e.TextMessage() != `No database named "nosuch".` || !strings.Contains(e.TextHint(), "no database yet") {
		t.Errorf("no databases: %q / %q", e.TextMessage(), e.TextHint())
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
