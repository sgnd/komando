package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestImportPgpass(t *testing.T) {
	p, err := importPgpass(writeTemp(t, "pgpass", "db.lan:5432:shop:app:se\\:cret\n*:*:*:x:y\n10.0.0.5:5432:shop:ro:pw\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Conns) != 2 || p.Conns[0].Name != "shop" || p.Conns[1].Name != "shop-2" {
		t.Fatalf("conns: %+v", p.Conns)
	}
	if p.Secrets["shop-pass"] != "se:cret" || strings.Contains(p.Conns[0].URL, "cret") {
		t.Errorf("password must move to the vault: %q / %q", p.Secrets["shop-pass"], p.Conns[0].URL)
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "wildcard") {
		t.Errorf("wildcard line should be reported: %v", p.Notes)
	}
}

func TestImportEnv(t *testing.T) {
	p, err := importEnv(writeTemp(t, ".env", "export DATABASE_URL=postgres://app:pw@db:5432/app\nREDIS_URL='redis://default:rpw@cache:6379/0'\nSENTRY_URL=https://x@s/1\nPLAIN=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Conns) != 2 || p.Conns[0].Name != "database" || p.Conns[1].Name != "redis" {
		t.Fatalf("conns: %+v", p.Conns)
	}
	if p.Conns[1].PasswordRef != "secret:redis-pass" || p.Secrets["redis-pass"] != "rpw" {
		t.Errorf("redis password: %q %q", p.Conns[1].PasswordRef, p.Secrets["redis-pass"])
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "SENTRY_URL") {
		t.Errorf("unknown URL should be reported: %v", p.Notes)
	}
}

func TestImportMycnf(t *testing.T) {
	p, err := importMycnf(writeTemp(t, "my.cnf", "[client]\nuser=root\npassword=\"top\"\nhost=db\ndatabase=shop\n[mysqld]\ndatadir=/x\n[client_reports]\nuser=ro\nsocket=/tmp/s\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Conns) != 1 || p.Conns[0].Name != "shop" || p.Secrets["shop-pass"] != "top" {
		t.Fatalf("conns: %+v secrets %v", p.Conns, len(p.Secrets))
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "socket") {
		t.Errorf("socket-only section should be reported: %v", p.Notes)
	}
}
