package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

// scriptTerm feeds lines to the shell and keeps what it writes.
type scriptTerm struct {
	lines  []string
	out    strings.Builder
	prompt string
}

func (s *scriptTerm) ReadLine() (string, error) {
	if len(s.lines) == 0 {
		return "", io.EOF
	}
	l := s.lines[0]
	s.lines = s.lines[1:]
	return l, nil
}
func (s *scriptTerm) SetPrompt(p string)          { s.prompt = p }
func (s *scriptTerm) Write(b []byte) (int, error) { return s.out.Write(b) }

func TestStatementDone(t *testing.T) {
	for text, want := range map[string]bool{
		"select 1;":              true,
		"select 1":               false,
		"select ';'":             false,
		"select ';';":            true,
		"select 'it''s';":        true,
		"select 1 -- trailing ;": false,
		"select 1; -- done":      true,
		"select /* ; */ 1":       false,
		"select $$ ; $$;":        true,
		"create function f() as $body$ begin; end; $body$": false,
		"select `a;b` from t;":                             true,
		"select \"x;\";":                                   true,
	} {
		if got := statementDone(text); got != want {
			t.Errorf("statementDone(%q) = %v, want %v", text, got, want)
		}
	}
}

// TestSQLShell drives the shell on a SQLite file: reads, multi-line input,
// the read-only guard, expanded rows and meta commands.
func TestSQLShell(t *testing.T) {
	setHome(t, t.TempDir())
	path := filepath.Join(t.TempDir(), "app.db")
	c := &store.Conn{Name: "app", Kind: "sqlite", URL: "sqlite://" + path}
	st := &store.State{Settings: store.DefaultSettings()}
	tg, _ := driver.Parse(c.URL)
	db, err := dbx.Open(context.Background(), c.URL, tg, "", nil, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec("create table users (id integer primary key, name text); insert into users values (1, 'ana'), (2, 'budi');")

	run := func(write bool, lines ...string) string {
		tm := &scriptTerm{lines: lines}
		sh := &sqlShell{cl: tcl, db: db, st: st, conn: c, kind: "sqlite", write: write, term: tm}
		sh.reopen = func(bool) error { return nil } // the same SQLite file
		sh.run(context.Background())
		return tm.out.String()
	}
	o := run(false, "select name", "from users", "order by id;", `select * from users where id = 2\G`, `\d`, `\d users`, "delete from users;", `\x`, "select 1 as one;", `\nope`, `\q`)
	for _, want := range []string{"ana", "budi", "(2 rows)", "-[ RECORD 1 ]", "name | budi", "users", "id", "primary key",
		"the shell is read-only", "Expanded display is on.", "one | 1", "Invalid command \\nope"} {
		if !strings.Contains(o, want) {
			t.Errorf("output lacks %q:\n%s", want, o)
		}
	}
	o = run(true, "insert into users values (3, 'cici');", "select count(*) as n from users;")
	if !strings.Contains(o, "1 row affected") || !strings.Contains(o, "3") {
		t.Errorf("write shell:\n%s", o)
	}
	// destructive SQL: the person types the conn's name, as on the command line
	o = run(true, "drop table users;", "nope")
	if !strings.Contains(o, "Not run.") {
		t.Errorf("destructive SQL without the name:\n%s", o)
	}
	o = run(true, "select count(*) as n from users;")
	if !strings.Contains(o, "3") {
		t.Errorf("the table must still be there:\n%s", o)
	}
	// \write asks, allows changes, and goes back to read-only
	o = run(false, `\write`, "n", "insert into users values (4, 'dodi');", `\write`, "y", "insert into users values (4, 'dodi');", `\write`, "insert into users values (5, 'eka');")
	for _, want := range []string{"Still read-only.", "Changes are allowed now.", "1 row affected", "Read-only again."} {
		if !strings.Contains(o, want) {
			t.Errorf("\\write: output lacks %q:\n%s", want, o)
		}
	}
	if strings.Count(o, "the shell is read-only") != 2 {
		t.Errorf("\\write: the inserts before and after must be refused:\n%s", o)
	}
	o = run(true, "drop table users;", "app", "select count(*) from users;")
	if !strings.Contains(o, "no such table") {
		t.Errorf("the typed name runs it:\n%s", o)
	}
	if o = run(false, "select 'unfinished"); strings.Contains(o, "unfinished") {
		t.Errorf("an unfinished statement must not run:\n%s", o)
	}
}

func TestDBShellDryRunContactsNothing(t *testing.T) {
	setHome(t, t.TempDir())
	saved, savedG := tcl.terminal, tcl.flags
	defer func() { tcl.terminal, tcl.flags = saved, savedG }()
	tcl.terminal = true
	tcl.flags.dryRun = true
	err := store.Update(func(st *store.State) error {
		st.Conns["far"] = &store.Conn{Name: "far", Kind: "postgres", URL: "postgres://app@10.255.255.1/app", Via: "no-such-host"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// the --via host does not exist: any attempt to open it would fail
	if err := runDBShell(tcl, context.Background(), "far", false); err != nil {
		t.Fatalf("dry run tried to connect: %v", err)
	}
}

func TestDBShellNeedsTerminal(t *testing.T) {
	saved := tcl.terminal
	defer func() { tcl.terminal = saved }()
	tcl.terminal = false
	if err := runDBShell(tcl, context.Background(), "x", false); err == nil || toErr(err).Code != "NEEDS_TERMINAL" {
		t.Errorf("want NEEDS_TERMINAL, got %v", err)
	}
}

func TestRedactSQL(t *testing.T) {
	for in, want := range map[string]string{
		"CREATE USER app WITH PASSWORD 's3cret'":                      "CREATE USER app WITH PASSWORD '***'",
		"alter role app encrypted password 'it''s'":                   "alter role app encrypted password '***'",
		"CREATE USER 'a'@'%' IDENTIFIED BY 'p@ss'":                    "CREATE USER 'a'@'%' IDENTIFIED BY '***'",
		"ALTER USER a IDENTIFIED WITH mysql_native_password BY \"x\"": "ALTER USER a IDENTIFIED WITH mysql_native_password BY '***'",
		"SET PASSWORD FOR 'a'@'%' = 'new'":                            "SET PASSWORD FOR 'a'@'%' = '***'",
		"select * from users where name = 'password'":                 "select * from users where name = 'password'",
		"ALTER ROLE x PASSWORD $$p$$":                                 "ALTER ROLE x PASSWORD '***'",
	} {
		if got := redactSQL(in); got != want {
			t.Errorf("redactSQL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDumpOpts(t *testing.T) {
	pg, err := dumpOpts{format: "custom", schemaOnly: true, tables: []string{"public.a"}}.args("postgres", []string{"pg_dump", "--dbname", "u"})
	if err != nil || strings.Join(pg, " ") != "pg_dump --dbname u --format=custom --schema-only --table=public.a" {
		t.Errorf("postgres: %v %v", pg, err)
	}
	my, err := dumpOpts{schemaOnly: true, tables: []string{"orders"}}.args("mysql", []string{"mysqldump", "--host", "h", "shop"})
	if err != nil || strings.Join(my, " ") != "mysqldump --host h --no-data shop orders" {
		t.Errorf("mysql: %v %v", my, err)
	}
	if _, err := (dumpOpts{format: "custom"}).args("mysql", []string{"mysqldump", "shop"}); err == nil {
		t.Error("custom format is PostgreSQL only")
	}
	dir := t.TempDir()
	arch, plain := filepath.Join(dir, "a.dump"), filepath.Join(dir, "a.sql")
	os.WriteFile(arch, []byte("PGDMP\x01\x0e"), 0o600)
	os.WriteFile(plain, []byte("-- SQL"), 0o600)
	if ok, _ := isPgArchive(tcl, arch); !ok {
		t.Error("PGDMP file not recognised")
	}
	if ok, _ := isPgArchive(tcl, plain); ok {
		t.Error("plain SQL taken for an archive")
	}
}
