package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// A Snowflake conn is always HTTPS with the certificate checked, so conn
// add keeps the URL as written and doctor has nothing to say about it;
// what Snowflake cannot do here says so before connecting.
func TestSnowflakeConns(t *testing.T) {
	invHome(t)
	raw := "snowflake://app_ro@myorg-acct/ANALYTICS/PUBLIC?warehouse=REPORTING&role=ANALYST_RO"
	d := mustRun(t, "conn", "add", "sf", raw)
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Conns["sf"].URL != raw || strings.Contains(fmt.Sprint(d["warnings"]), "TLS") {
		t.Errorf("saved %s, warnings %v", st.Conns["sf"].URL, d["warnings"])
	}
	if got := plainConn(st.Conns["sf"]); got != "" {
		t.Errorf("plainConn: %q", got)
	}
	wantCode(t, "USAGE", "conn", "add", "sf-tls", "snowflake://app@acct/db?tls=false")
	wantCode(t, "URL_HAS_PASSWORD", "conn", "add", "sf-pw", "snowflake://app:pw@acct/db")
	wantCode(t, "NOT_SUPPORTED", "db", "dump", "sf", "--to", t.TempDir()+"/s.sql")
	wantCode(t, "NOT_SUPPORTED", "db", "restore", "sf", "--from", "x.sql", "--dry-run")
	wantCode(t, "NOT_SUPPORTED", "db", "explain", "sf", "select 1", "--analyze")
	wantCode(t, "NOT_SUPPORTED", "db", "user", "add", "sf", "bob", "--password-ref", "secret:x")
	wantCode(t, "NOT_SUPPORTED", "db", "user", "rm", "sf", "bob")
	wantCode(t, "NOT_SUPPORTED", "db", "grant", "sf", "bob", "--role", "readers")
	// the classifier says what needs --write before anything connects
	wantCode(t, "WRITE_REQUIRES_FLAG", "db", "query", "sf", "insert into t values (1)")
	wantCode(t, "SQL_HIDDEN_CODE", "db", "query", "sf", "select 1 // a\x0bdrop table t")
	p, e := invRun(t, "policy", "check", "--for", "snowflake", "select system$cancel_query('x')")
	if p["risk"] != "destructive" || e == nil || e.Code != "POLICY_BLOCKED" {
		t.Errorf("policy check: %v %+v", p, e)
	}
}

func TestSnowflakeImport(t *testing.T) {
	p, err := importDBeaver(writeTemp(t, "data-sources.json", `{"connections":{
		"snowflake-1":{"name":"Warehouse","provider":"snowflake","configuration":{"host":"myorg-acct.snowflakecomputing.com","port":"443","database":"ANALYTICS","user":"app"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Conns) != 1 || p.Conns[0].URL != "snowflake://app@myorg-acct.snowflakecomputing.com:443/ANALYTICS" {
		t.Errorf("dbeaver snowflake: %+v", p.Conns)
	}
}
