package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// A SQL Server conn that crosses the network gets encrypt=true, whatever
// case its other options are written in; --via and this computer stay as
// written.
func TestSQLServerConnsCheckTLS(t *testing.T) {
	invHome(t)
	url := func(name string) string {
		st, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		return st.Conns[name].URL
	}
	d := mustRun(t, "conn", "add", "sales", "sqlserver://app@db.example.com/sales")
	if url("sales") != "sqlserver://app@db.example.com/sales?encrypt=true" || !strings.Contains(fmt.Sprint(d["warnings"]), "added encrypt=true") {
		t.Errorf("sqlserver: %s, %v", url("sales"), d)
	}
	mustRun(t, "host", "add", "jump", "deploy@10.0.0.3")
	for name, raw := range map[string]string{
		"s-plain": "sqlserver://app@db.example.com/sales?Encrypt=disable",
		"s-local": "sqlserver://app@127.0.0.1/sales",
	} {
		mustRun(t, "conn", "add", name, raw)
		if url(name) != raw {
			t.Errorf("%s: saved %s", name, url(name))
		}
	}
	mustRun(t, "conn", "add", "s-via", "mssql://app@10.0.0.5/sales", "--via", "jump")
	if url("s-via") != "mssql://app@10.0.0.5/sales" {
		t.Errorf("--via: %s", url("s-via"))
	}

	// doctor's fix replaces any spelling of encrypt= and drops tls=skip-verify
	for raw, want := range map[string]string{
		"sqlserver://app@db/sales":                              "sqlserver://app@db/sales?encrypt=true",
		"sqlserver://app@db/sales?Encrypt=false":                "sqlserver://app@db/sales?encrypt=true",
		"sqlserver://app@db/sales?encrypt=true&tls=skip-verify": "sqlserver://app@db/sales?encrypt=true",
		"sqlserver://app@db/sales?applicationintent=readonly":   "sqlserver://app@db/sales?applicationintent=readonly&encrypt=true",
	} {
		if got := verifiedTLSURL(raw, "sqlserver"); got != want {
			t.Errorf("verifiedTLSURL(%s) = %s, want %s", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"sqlserver://app@db.example.com/sales":                              "only the login is encrypted",
		"sqlserver://app@db.example.com/sales?encrypt=false":                "only the login is encrypted",
		"sqlserver://app@db.example.com/sales?encrypt=disable":              "travels unencrypted (encrypt=disable)",
		"sqlserver://app@db.example.com/sales?encrypt=true&tls=skip-verify": "not checked",
		"sqlserver://app@db.example.com/sales?encrypt=strict":               "",
	} {
		got := plainConn(&store.Conn{Name: "s", URL: raw})
		if want == "" && got != "" || !strings.Contains(got, want) {
			t.Errorf("plainConn(%s) = %q, want %q", raw, got, want)
		}
	}
	if w := weakTLS("", "sqlserver://app@db/sales?encrypt=true&tls=skip-verify"); len(w) != 1 || !strings.Contains(w[0], "skip-verify") {
		t.Errorf("weakTLS skip-verify: %v", w)
	}
	if w := weakTLS("", "sqlserver://app@db/sales?encrypt=disable"); len(w) != 1 || !strings.Contains(w[0], "unencrypted") {
		t.Errorf("weakTLS disable: %v", w)
	}

	// what SQL Server cannot do says so before connecting
	wantCode(t, "NOT_SUPPORTED", "db", "kill", "sales", "57")
	wantCode(t, "NOT_SUPPORTED", "db", "dump", "sales", "--to", t.TempDir()+"/s.sql")
	wantCode(t, "NOT_SUPPORTED", "db", "restore", "s-local", "--from", "x.sql", "--dry-run")
}

func TestSQLServerExplainOnlyPlans(t *testing.T) {
	p, err := classifyQuery("sqlserver", "delete from dbo.t", dbFlags{showplan: "text"})
	if err != nil || p.NeedsWrite() {
		t.Errorf("a planned delete needs --write: %+v %v", p, err)
	}
	if p, _ := classifyQuery("sqlserver", "delete from dbo.t", dbFlags{showplan: "profile"}); !p.NeedsWrite() {
		t.Error("explain --analyze runs the delete, so it needs --write")
	}
	if p, _ := classifyQuery("sqlserver", "exec dbo.p", dbFlags{showplan: "text"}); !p.NeedsWrite() {
		t.Error("a procedure is not only planned")
	}
	if got := redactSQL("CREATE LOGIN bob WITH PASSWORD = N'Pa''ss', CHECK_POLICY = ON"); got != "CREATE LOGIN bob WITH PASSWORD = N'***', CHECK_POLICY = ON" {
		t.Errorf("redact: %s", got)
	}
}
