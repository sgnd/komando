package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// personalDB is a SQLite file with one customer, reached as a protected
// conn (prod) and an ordinary one (dev).
func personalDB(t *testing.T) {
	t.Helper()
	invHome(t)
	dir := t.TempDir()
	// two files: a conn on the same address as a protected one is protected too
	mustRun(t, "conn", "add", "prod", "sqlite://"+filepath.Join(dir, "prod.db"), "--protected")
	mustRun(t, "conn", "add", "dev", "sqlite://"+filepath.Join(dir, "dev.db"))
	for _, conn := range []string{"prod", "dev"} {
		mustRun(t, "db", "query", conn, "--write", "--yes", "create table users (id int, name text, email text, phone text, card text)")
		mustRun(t, "db", "query", conn, "--write", "--yes", "insert into users values (1, 'Ada Lovelace', 'ada@example.com', '+44 20 7946 0958', '4111 1111 1111 1111')")
	}
}

// customer is the first row of `select * from users` on conn.
func customer(t *testing.T, conn string) []any {
	t.Helper()
	d := mustRun(t, "db", "query", conn, "select * from users")
	return d["results"].([]any)[0].(map[string]any)["rows"].([]any)[0].([]any)
}

func TestPersonalHiddenFromAgentOnProtected(t *testing.T) {
	personalDB(t)
	shown := []any{float64(1), "Ada Lovelace", "ada@example.com", "+44 20 7946 0958", "4111 1111 1111 1111"}
	hidden := []any{float64(1), "Ada Lovelace", "[hidden: email]", "[hidden: phone]", "[hidden: card]"}
	same := func(got, want []any) bool { return strings.Join(strs(got), "|") == strings.Join(strs(want), "|") }

	if got := customer(t, "prod"); !same(got, shown) {
		t.Errorf("a person sees the data: %v", got)
	}
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	if got := customer(t, "prod"); !same(got, hidden) {
		t.Errorf("an agent on a protected conn: %v", got)
	}
	if got := customer(t, "dev"); !same(got, shown) {
		t.Errorf("an agent on an ordinary conn (setting protected): %v", got)
	}

	mustRun(t, "config", "set", "mask_personal", "all") // more hiding needs no yes
	if got := customer(t, "dev"); !same(got, hidden) {
		t.Errorf("setting all: %v", got)
	}
	e := wantCode(t, "SAFETY_SETTING", "config", "set", "mask_personal", "off")
	if !strings.Contains(e.Message+e.Hint, "personal") {
		t.Errorf("why: %+v", e)
	}
	os.Unsetenv("KOMANDO_AGENT") // a person turns it off
	mustRun(t, "config", "set", "mask_personal", "off", "--yes")
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	if got := customer(t, "prod"); !same(got, shown) {
		t.Errorf("setting off: %v", got)
	}
	wantCode(t, "USAGE", "config", "set", "mask_personal", "sometimes")
}

func TestPersonalMaskColumns(t *testing.T) {
	personalDB(t)
	mustRun(t, "conn", "edit", "dev", "--option", "mask_columns=Name  card")
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	got := strs(customer(t, "dev"))
	want := []string{"1", "[hidden: column]", "[hidden: email]", "[hidden: phone]", "[hidden: column]"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("mask_columns on an ordinary conn: %v", got)
	}

	// CSV goes through the same masking
	var buf bytes.Buffer
	saved := out.P.W
	out.P.W = &buf
	root := newRoot()
	root.SetArgs([]string{"db", "query", "prod", "-o", "csv", "select email, card from users"})
	err := root.Execute()
	out.P.W = saved
	if err != nil || !strings.Contains(buf.String(), "[hidden: email],[hidden: card]") || strings.Contains(buf.String(), "ada@") {
		t.Errorf("CSV for an agent: %q %v", buf.String(), err)
	}
}

func TestPersonalHiddenValueNotWritten(t *testing.T) {
	personalDB(t)
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	wantCode(t, "HIDDEN_VALUE", "db", "query", "dev", "--write", "update users set email = '[hidden: email]' where id = 1")
	wantCode(t, "HIDDEN_VALUE", "db", "query", "dev", "--write", "--arg", "[hidden: phone]", "update users set phone = ? where id = 1")
	os.Unsetenv("KOMANDO_AGENT")
	resetApproval()
	if got := strs(customer(t, "dev")); got[2] != "ada@example.com" || got[3] != "+44 20 7946 0958" {
		t.Errorf("the real values stay: %v", got)
	}
}

func TestPersonalOnlyForDataCommands(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "admin@web1.example.com", "--protected")
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	for _, args := range [][]string{{"host", "show", "web1"}, {"list"}} {
		b, _ := json.Marshal(mustRun(t, args...))
		if strings.Contains(string(b), "[hidden") || !strings.Contains(string(b), "web1.example.com") {
			t.Errorf("%v: komando's own inventory is never hidden: %s", args, b)
		}
	}
}

func strs(v []any) []string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprint(x)
	}
	return s
}
