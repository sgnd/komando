package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/snippet"
)

// clientSnippet is a client built-in of one type, at one tier, whose call
// is fn (nil: it only answers). Its one variable is a plain word.
func clientSnippet(typ string, tier capability.Tier, fn func(c snippet.Client, v snippet.Values) (any, error)) snippet.Builtin {
	name := map[string]string{"host": "fs-list", "database": "db-info", "cache": "cache-info", "cluster": "cluster-status"}[typ]
	if fn == nil {
		fn = func(snippet.Client, snippet.Values) (any, error) { return map[string]any{"ok": true}, nil }
	}
	return snippet.Builtin{
		Name: name, Type: typ, Replaces: "test", Reader: "a test", Tier: tier, Shape: name + "/1",
		Vars: []snippet.Var{{Name: "word", Channel: snippet.Text, Pattern: regexp.MustCompile(`^[a-z]+$`), MaxLen: 4, Longest: "abcd"}},
		Run:  func(_ context.Context, c snippet.Client, v snippet.Values) (any, error) { return fn(c, v) },
	}
}

// fakeEntry is an entry that opens a fake client, and counts how often it
// was opened and closed.
func fakeEntry(e snippetEntry, client snippet.Client, opened, closed *int) snippetEntry {
	e.with = func(_ context.Context, use func(snippet.Client) error) error {
		*opened++
		defer func() { *closed++ }()
		return use(client)
	}
	return e
}

// clientRun runs b against the entry named target, whose client is the fake,
// as `snippet exec NAME TARGET` does after it chose the entry.
func clientRun(t *testing.T, b snippet.Builtin, target string, client snippet.Client, kv map[string]string) (opened, closed int, printed string, err error) {
	t.Helper()
	closeStoreAtEnd(t)
	resetApproval()
	st, lerr := loadState()
	if lerr != nil {
		t.Fatal(lerr)
	}
	e, rerr := resolveSnippetEntry(tcl, st, b, target)
	if rerr != nil {
		return 0, 0, "", rerr
	}
	e = fakeEntry(e, client, &opened, &closed)
	var buf bytes.Buffer
	saved := tcl.out.W
	tcl.out.W = &buf
	defer func() { tcl.out.W = saved }()
	err = runSnippetEntry(tcl, context.Background(), st, b, e, kv)
	return opened, closed, buf.String(), err
}

func clientCode(err error) string {
	var e *out.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// A client snippet runs against the one entry of its type, and a target of
// another type, a Windows host, a Swarm cluster or a selector of many are
// refused before anything is opened.
func TestResolveSnippetEntry(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@127.0.0.1:1")
	mustRun(t, "host", "ssh", "add", "web2", "u@127.0.0.1:2")
	mustRun(t, "host", "ssh", "add", "win1", "u@127.0.0.1:3", "--os", "windows")
	mustRun(t, "conn", "add", "lite", "sqlite://"+filepath.Join(t.TempDir(), "app.db"))
	mustRun(t, "conn", "add", "cash", "redis://127.0.0.1:1")
	for _, tc := range []struct {
		name, typ, target, want string
	}{
		{"a host", "host", "web1", ""},
		{"a database", "database", "lite", ""},
		{"a cache", "cache", "cash", ""},
		{"a conn for a host snippet", "host", "lite", "SNIPPET_TYPE_UNSUPPORTED"},
		{"a host for a database snippet", "database", "web1", "SNIPPET_TYPE_UNSUPPORTED"},
		{"a Windows host", "host", "win1", "SNIPPET_OS_UNSUPPORTED"},
		{"a Swarm manager (a host) for a cluster snippet", "cluster", "web1", "SNIPPET_OS_UNSUPPORTED"},
		{"a database conn for a cluster snippet", "cluster", "lite", "NO_MATCHING_TARGETS"},
		{"a selector of many hosts", "host", "web1,web2", "USAGE"},
		{"a name nothing has", "host", "nobody", "TARGET_NOT_FOUND"},
	} {
		b := clientSnippet(tc.typ, capability.Read, nil)
		closeStoreAtEnd(t)
		st, err := loadState()
		if err != nil {
			t.Fatal(err)
		}
		_, err = resolveSnippetEntry(tcl, st, b, tc.target)
		if clientCode(err) != tc.want {
			t.Errorf("%s: code %q (%v), want %q", tc.name, clientCode(err), err, tc.want)
		}
	}
}

// A bad variable stops the run before any connection is opened.
func TestClientSnippetChecksVariablesFirst(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "lite", "sqlite://"+filepath.Join(t.TempDir(), "app.db"))
	b := clientSnippet("database", capability.Read, nil)
	for _, kv := range []map[string]string{{"word": "TOO LONG; drop"}, {"other": "x"}} {
		opened, _, _, err := clientRun(t, b, "lite", struct{}{}, kv)
		if err == nil || opened != 0 {
			t.Errorf("--var %v: error %v after %d connections, want it refused before any", kv, err, opened)
		}
	}
}

// A read snippet runs, prints the snippet's JSON contract and closes its
// client; a change on a protected entry asks first; dangerous needs
// --allow-dangerous; a person-only snippet refuses a script.
func TestClientSnippetTiers(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "lite", "sqlite://"+filepath.Join(t.TempDir(), "app.db"))
	mustRun(t, "conn", "add", "prod", "sqlite://"+filepath.Join(t.TempDir(), "prod.db"), "--protected")

	read := clientSnippet("database", capability.Read, nil)
	opened, closed, printed, err := clientRun(t, read, "prod", struct{}{}, nil)
	if err != nil || opened != 1 || closed != 1 {
		t.Fatalf("a read on a protected conn: %v, opened %d, closed %d; want it to run and close", err, opened, closed)
	}
	for _, want := range []string{`"snippet":"db-info"`, `"shape":"db-info/1"`, `"target":"prod"`, `"ok":true`} {
		if !strings.Contains(printed, want) {
			t.Errorf("the answer lacks %s:\n%s", want, printed)
		}
	}

	change := clientSnippet("database", capability.Change, nil)
	if opened, _, _, err := clientRun(t, change, "prod", struct{}{}, nil); clientCode(err) != "PROTECTED_TARGET" || opened != 0 {
		t.Errorf("a change on a protected conn without --yes: %v, opened %d; want PROTECTED_TARGET and nothing opened", err, opened)
	}
	if opened, _, _, err := clientRun(t, change, "lite", struct{}{}, nil); err != nil || opened != 1 {
		t.Errorf("a change on a plain conn: %v, opened %d; want it to run", err, opened)
	}
	setGate(tcl, true, gateYes)
	if opened, _, _, err := clientRun(t, change, "prod", struct{}{}, nil); err != nil || opened != 1 {
		t.Errorf("a change on a protected conn with --yes: %v, opened %d; want it to run", err, opened)
	}
	setGate(tcl, false, gateYes)

	danger := clientSnippet("database", capability.Dangerous, nil)
	if opened, _, _, err := clientRun(t, danger, "lite", struct{}{}, nil); clientCode(err) != "POLICY_BLOCKED" || opened != 0 {
		t.Errorf("a dangerous snippet without --allow-dangerous: %v, opened %d; want POLICY_BLOCKED and nothing opened", err, opened)
	}
	setGate(tcl, true, gateAllowDangerous)
	defer setGate(tcl, false, gateAllowDangerous)
	// a protected conn asks for --yes as well: the entries are part of the stop
	if opened, _, _, err := clientRun(t, danger, "prod", struct{}{}, nil); clientCode(err) != "PROTECTED_TARGET" || opened != 0 {
		t.Errorf("a dangerous snippet on a protected conn with --allow-dangerous only: %v, opened %d; want PROTECTED_TARGET and nothing opened", err, opened)
	}
	if opened, _, _, err := clientRun(t, danger, "lite", struct{}{}, nil); err != nil || opened != 1 {
		t.Errorf("a dangerous snippet with --allow-dangerous: %v, opened %d; want it to run", err, opened)
	}

	person := clientSnippet("database", capability.Person, nil)
	if opened, _, _, err := clientRun(t, person, "lite", struct{}{}, nil); clientCode(err) != "NEEDS_PERSON" || opened != 0 {
		t.Errorf("a person-only snippet in a script: %v, opened %d; want NEEDS_PERSON and nothing opened", err, opened)
	}
}

// A change writes an audit record with the snippet and the conn, a read
// writes none (as today's db and cache reads), and a failing call still
// closes its client and says why in the record.
func TestClientSnippetAudit(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "lite", "sqlite://"+filepath.Join(t.TempDir(), "app.db"))

	change := clientSnippet("database", capability.Change, func(snippet.Client, snippet.Values) (any, error) {
		return nil, out.Errf(out.ExitConnect, "DB_CONNECT", "check it", "refused")
	})
	opened, closed, _, err := clientRun(t, change, "lite", struct{}{}, nil)
	if clientCode(err) != "DB_CONNECT" || opened != 1 || closed != 1 {
		t.Fatalf("a failing change: %v, opened %d, closed %d; want its error and a closed client", err, opened, closed)
	}
	a := lastAudit(t)
	conns, _ := a["conns"].([]any)
	if a["command"] != "snippet.exec" || a["remote"] != "snippet db-info" || a["ok"] != false || a["error"] != "DB_CONNECT" || a["risk"] != "write" || len(conns) != 1 || conns[0] != "lite" {
		t.Errorf("audit record %v: want snippet.exec, remote %q, conns [lite], risk write, failed with DB_CONNECT", a, "snippet db-info")
	}

	// a read writes no record: the last one is still the change's
	read := clientSnippet("database", capability.Read, nil)
	if _, _, _, err := clientRun(t, read, "lite", struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	if b := lastAudit(t); b["ts"] != a["ts"] {
		t.Errorf("a read wrote the audit record %v", b)
	}
}

// The database client is read-only: a snippet that tries to write is
// refused by the database, not by a check of ours that a body could skip.
func TestDatabaseClientIsReadOnly(t *testing.T) {
	invHome(t)
	path := filepath.Join(t.TempDir(), "app.db")
	mustRun(t, "conn", "add", "lite", "sqlite://"+path)
	mustRun(t, "database", "sqlite", "query", "lite", "--write", "create table t (id int)")
	var wrote, read error
	b := clientSnippet("database", capability.Read, func(c snippet.Client, _ snippet.Values) (any, error) {
		db := c.(*dbClient).db
		_, wrote = db.Exec("insert into t values (1)")
		var n int
		read = db.QueryRow("select count(*) from t").Scan(&n)
		return map[string]any{"rows": n}, nil
	})
	closeStoreAtEnd(t)
	resetApproval()
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	e, err := resolveSnippetEntry(tcl, st, b, "lite")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	saved := tcl.out.W
	tcl.out.W = &buf
	defer func() { tcl.out.W = saved }()
	if err := runSnippetEntry(tcl, context.Background(), st, b, e, nil); err != nil {
		t.Fatal(err)
	}
	if wrote == nil {
		t.Error("an insert through the database client worked; it must be opened read-only")
	}
	if read != nil && !errors.Is(read, sql.ErrNoRows) {
		t.Errorf("a select through the database client failed: %v", read)
	}
}

// Nothing registers a client snippet that changes a host until a guard for
// it is wired (fs-write waits on the write rule, Audit Q1): the runner
// refuses it, so a later built-in cannot reach SFTP without one.
func TestHostClientChangeSnippetIsRefused(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@127.0.0.1:1")
	b := clientSnippet("host", capability.Change, nil)
	opened, _, _, err := clientRun(t, b, "web1", struct{}{}, nil)
	if err == nil || opened != 0 {
		t.Errorf("a host client snippet at change tier: %v, opened %d; want it refused with nothing opened", err, opened)
	}
}
