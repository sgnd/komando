package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// An Oracle conn that crosses the network gets tls=true (TCPS); --via and
// this computer stay as written.
func TestOracleConnsCheckTLS(t *testing.T) {
	invHome(t)
	url := func(name string) string {
		st, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		return st.Conns[name].URL
	}
	d := mustRun(t, "conn", "add", "erp", "oracle://app@db.example.com/ERP")
	if url("erp") != "oracle://app@db.example.com/ERP?tls=true" || !strings.Contains(fmt.Sprint(d["warnings"]), "added tls=true") {
		t.Errorf("oracle: %s, %v", url("erp"), d)
	}
	mustRun(t, "host", "add", "jump", "deploy@10.0.0.3")
	for name, raw := range map[string]string{
		"o-plain": "oracle://app@db.example.com/ERP?tls=false",
		"o-local": "oracle://app@127.0.0.1/FREEPDB1",
	} {
		mustRun(t, "conn", "add", name, raw)
		if url(name) != raw {
			t.Errorf("%s: saved %s", name, url(name))
		}
	}
	mustRun(t, "conn", "add", "o-via", "oracle://app@10.0.0.5/ERP", "--via", "jump")
	if url("o-via") != "oracle://app@10.0.0.5/ERP" {
		t.Errorf("--via: %s", url("o-via"))
	}
	for raw, want := range map[string]string{
		"oracle://app@db/ERP":                 "oracle://app@db/ERP?tls=true",
		"oracle://app@db/ERP?tls=skip-verify": "oracle://app@db/ERP?tls=true",
	} {
		if got := verifiedTLSURL(raw, "oracle"); got != want {
			t.Errorf("verifiedTLSURL(%s) = %s, want %s", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"oracle://app@db.example.com/ERP":                 "travels without TLS",
		"oracle://app@db.example.com/ERP?tls=false":       "travels without TLS",
		"oracle://app@db.example.com/ERP?tls=skip-verify": "not checked",
		"oracle://app@db.example.com/ERP?tls=true":        "",
	} {
		got := plainConn(&store.Conn{Name: "o", URL: raw})
		if want == "" && got != "" || !strings.Contains(got, want) {
			t.Errorf("plainConn(%s) = %q, want %q", raw, got, want)
		}
	}
	if w := weakTLS("", "oracle://app@db/ERP?tls=skip-verify"); len(w) != 1 || !strings.Contains(w[0], "skip-verify") {
		t.Errorf("weakTLS skip-verify: %v", w)
	}
	if w := weakTLS("", "oracle://app@db/ERP?tls=false"); len(w) != 1 || !strings.Contains(w[0], "without TLS") {
		t.Errorf("weakTLS false: %v", w)
	}
	// what Oracle cannot do says so before connecting
	wantCode(t, "NOT_SUPPORTED", "db", "dump", "erp", "--to", t.TempDir()+"/o.sql")
	wantCode(t, "NOT_SUPPORTED", "db", "restore", "o-local", "--from", "x.sql", "--dry-run")
	wantCode(t, "NOT_SUPPORTED", "db", "explain", "o-local", "select 1 from dual", "--analyze")
}

func TestOracleExplainAndRedact(t *testing.T) {
	p, err := classifyQuery("oracle", "delete from orders", dbFlags{showplan: "text"})
	if err != nil || p.NeedsWrite() {
		t.Errorf("a planned delete needs --write: %+v %v", p, err)
	}
	if p, _ := classifyQuery("oracle", "begin p; end;", dbFlags{showplan: "text"}); !p.NeedsWrite() {
		t.Error("a block is not only planned")
	}
	// EXPLAIN PLAN takes CREATE TABLE, CREATE INDEX and ALTER INDEX without running them
	for _, q := range []string{"create index i on t (c)", "create unique index i on t (c)", "create table t2 as select * from t", "alter index i rebuild"} {
		p, err := classifyQuery("oracle", q, dbFlags{showplan: "text"})
		if err != nil || p.NeedsWrite() || p.Statements[0].NoTx {
			t.Errorf("%s: a planned DDL needs no --write: %+v %v", q, p, err)
		}
	}
	for _, q := range []string{"drop table t", "create table t2 as select * from t@prodlink", "create or replace function f return number is begin return 1; end;"} {
		if p, _ := classifyQuery("oracle", q, dbFlags{showplan: "text"}); !p.NeedsWrite() {
			t.Errorf("%s: EXPLAIN PLAN cannot plan it, so it is not only planned", q)
		}
	}
	for in, want := range map[string]string{
		`create user bob identified by "Pa'ss"`:                              `create user bob identified by '***'`,
		`alter user bob identified by Secret1 account unlock`:                `alter user bob identified by *** account unlock`,
		`begin execute immediate 'create user "B" identified by "x"'; end;`:  `begin execute immediate 'create user "B" identified by '***''; end;`,
		`CREATE USER a IDENTIFIED BY PASSWORD '*hash'`:                       `CREATE USER a IDENTIFIED BY PASSWORD '***'`,
		`alter user bob identified by NewPw1 replace OldSecret9`:             `alter user bob identified by *** replace ***`,
		`alter user bob identified by "N3w" replace "Old pw" account unlock`: `alter user bob identified by '***' replace '***' account unlock`,
		`alter user bob identified by values 'S:ABCDEF0123'`:                 `alter user bob identified by values '***'`,
		`create user bob identified/**/by Secret1`:                           `create user bob identified/**/by ***`,
		"create user bob identified -- x\n by \"Pw\"":                        "create user bob identified -- x\n by '***'",
		`alter user bob identified /* a */ by "N" /* b */ replace Old1`:      `alter user bob identified /* a */ by '***' /* b */ replace ***`,
	} {
		if got := redactSQL(in); got != want {
			t.Errorf("redact %s: %s, want %s", in, got, want)
		}
	}
	if !shellDone("oracle", "begin\n null;\nend;\n/") || shellDone("oracle", "begin\n null;\nend;") || !shellDone("oracle", "select 1 from dual;") {
		t.Error("shellDone")
	}
	// Oracle reads \ as itself, q'[...]' may hold ', and # and $ are part of names
	for text, want := range map[string]bool{
		`select 'C:\' from dual;`:        true,
		`select q'[it's]' from dual;`:    true,
		`select q'[it's;]' from dual`:    false,
		"select serial# from v$session;": true,
		"select a$b$ from t;":            true,
		"select 'x;' from dual":          false,
		"select 1 from dual; -- done":    true,
		"select 1 from dual -- ;":        false,
		"select 1 /* ; */ from dual":     false,
		`select "a;b" from dual;`:        true,
		"select 'never closed;":          false,
		"select café from dual;":         true, // refused when it runs, with a clear error
	} {
		if got := shellDone("oracle", text); got != want {
			t.Errorf("shellDone(oracle, %q) = %v, want %v", text, got, want)
		}
	}
}
