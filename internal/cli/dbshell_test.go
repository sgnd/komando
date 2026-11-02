package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

func shellFor(t *testing.T, url, addr string, write bool) ([]string, []string) {
	t.Helper()
	tg, err := driver.Parse(url)
	if err != nil {
		t.Fatal(err)
	}
	argv, env, err := shellCommand(&store.Conn{URL: url}, tg, "s3cret-pw", addr, write)
	if err != nil {
		t.Fatal(err)
	}
	return argv, env
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestShellCommand(t *testing.T) {
	t.Setenv("KOMANDO_VAULT_PASS", "vault-pass")

	argv, env := shellFor(t, "postgres://app@db.internal:5432/app?sslmode=verify-full", "127.0.0.1:50123", false)
	for _, want := range []string{"PGHOST=db.internal", "PGHOSTADDR=127.0.0.1", "PGPORT=50123", "PGSSLMODE=verify-full",
		"PGPASSWORD=s3cret-pw", "PGOPTIONS=-c default_transaction_read_only=on"} {
		if !has(env, want) {
			t.Errorf("postgres env lacks %s", want)
		}
	}
	if strings.Contains(strings.Join(argv, " "), "s3cret-pw") {
		t.Error("password on the command line")
	}
	if _, env := shellFor(t, "postgres://app@db.internal:5432/app", "db.internal:5432", true); has(env, "PGOPTIONS=-c default_transaction_read_only=on") || has(env, "PGHOSTADDR=db.internal") {
		t.Errorf("--write or direct connection set extra options: %v", env)
	}

	argv, env = shellFor(t, "mysql://shop@db.internal:3306/shop", "db.internal:3306", false)
	if !has(argv, "--init-command=SET SESSION TRANSACTION READ ONLY") || !has(env, "MYSQL_PWD=s3cret-pw") || argv[len(argv)-1] != "shop" {
		t.Errorf("mysql: %v", argv)
	}
	if argv, _ := shellFor(t, "sqlite:///tmp/app.db", "", false); !has(argv, "-readonly") {
		t.Errorf("sqlite: %v", argv)
	}
	if argv, _ := shellFor(t, "sqlite:///tmp/app.db", "", true); has(argv, "-readonly") {
		t.Errorf("sqlite --write: %v", argv)
	}
	for _, e := range env {
		if strings.HasPrefix(e, "KOMANDO_VAULT_PASS=") {
			t.Error("vault passphrase passed to the client")
		}
	}

	tg, _ := driver.Parse("mysql://shop@db.internal:3306/shop?tls=true")
	if _, _, err := shellCommand(&store.Conn{}, tg, "x", "127.0.0.1:5000", false); err == nil || toErr(err).Code != "TLS_THROUGH_FORWARD" {
		t.Errorf("mysql TLS through a forward: %v", err)
	}
}

func TestDBShellDryRunContactsNothing(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	saved, savedG := interactive, g
	defer func() { interactive, g = saved, savedG }()
	interactive = func() bool { return true }
	g.dryRun = true
	err := store.Update(func(st *store.State) error {
		st.Conns["far"] = &store.Conn{Name: "far", Kind: "postgres", URL: "postgres://app@10.255.255.1/app", Via: "no-such-host"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// the --via host does not exist: any attempt to open it would fail
	if err := runDBShell(context.Background(), "far", false); err != nil {
		t.Fatalf("dry run tried to connect: %v", err)
	}
}

func TestDBShellNeedsTerminal(t *testing.T) {
	saved := interactive
	defer func() { interactive = saved }()
	interactive = func() bool { return false }
	if err := runDBShell(context.Background(), "x", false); err == nil || toErr(err).Code != "NEEDS_TERMINAL" {
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
	if ok, _ := isPgArchive(arch); !ok {
		t.Error("PGDMP file not recognised")
	}
	if ok, _ := isPgArchive(plain); ok {
		t.Error("plain SQL taken for an archive")
	}
}
