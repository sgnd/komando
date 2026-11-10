package driver

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestClassifySnowflake(t *testing.T) {
	cases := []struct {
		sql  string
		want Risk
		rule string
	}{
		// reads
		{"select * from orders where id = ?", RiskRead, ""},
		{`select 'it\'s; drop table t' as x`, RiskRead, ""},
		{`select 'a\\'; select 1`, RiskRead, ""},
		{"select 'a''b; drop table t' as x", RiskRead, ""},
		{`select "drop", "a""b; drop table t" from "T"`, RiskRead, ""},
		{"select $$it's; drop table t$$ as x", RiskRead, ""},
		{"select 1 // it's; drop table t\n as x", RiskRead, ""},
		{"select 1 -- it's; drop table t\r\n as x", RiskRead, ""},
		{"select 1 /* it's; drop table t */ as x", RiskRead, ""},
		{"select $1, $2 from @my_stage (file_format => 'csv')", RiskRead, ""},
		{"select v:customer.name::string from events", RiskRead, ""},
		{"with x as (select 1 as a) select * from x", RiskRead, ""},
		{"show tables in schema analytics.public", RiskRead, ""},
		{"show grants to role analyst", RiskRead, ""},
		{"describe table orders", RiskRead, ""},
		{"desc view v", RiskRead, ""},
		{"list @my_stage", RiskRead, ""},
		{"explain select * from orders", RiskRead, ""},
		{"explain using text delete from orders", RiskRead, ""},
		{"show warehouses ->> select \"name\" from $1 where \"state\" = 'STARTED'", RiskRead, ""},
		{"select system$clustering_information('orders'), system$typeof(1)", RiskRead, ""},
		{"select * from table(information_schema.query_history()) where execution_status = 'RUNNING'", RiskRead, ""},
		{"select * from table(db.information_schema.query_history())", RiskRead, ""},
		{"select f.value from table(flatten(input => parse_json('[1, 2]'))) f", RiskRead, ""},
		{"select * from table(result_scan(last_query_id()))", RiskRead, ""},
		{"select * from table(generator(rowcount => 3))", RiskRead, ""},
		{"select * from table('orders')", RiskRead, ""},
		{"select * from t, lateral flatten(input => t.v)", RiskRead, ""},
		{"select get_ddl('table', 'orders')", RiskRead, ""},
		{"use warehouse reporting", RiskRead, ""},
		{"set x = 5", RiskRead, ""},
		{"create table user_roles (id int) as select 1", RiskWrite, ""},
		// writes: sent alone, a dry run only reports them
		{"insert into orders values (1, 'pen')", RiskWrite, ""},
		{"update orders set item = 'x' where id = 1", RiskWrite, ""},
		{"merge into t using s on t.id = s.id when matched then update set v = s.v", RiskWrite, ""},
		{"create table t (id int)", RiskWrite, ""},
		{"create table policy (id int)", RiskWrite, ""},
		{"create transient table if not exists t (id int)", RiskWrite, ""},
		{"alter table t add column c int", RiskWrite, ""},
		{"alter session set query_tag = 'x'", RiskWrite, ""},
		{"undrop table t", RiskWrite, ""},
		{"comment on table t is 'x'", RiskWrite, ""},
		{"copy into t from @my_stage/data.csv", RiskWrite, ""},
		{"create procedure p() returns int language sql as $$ begin delete from t; return 1; end $$", RiskWrite, ""},
		{"unset x", RiskWrite, ""},
		{"select 1 ->> insert into t select * from $1", RiskWrite, ""},
		// destructive
		{"drop table t", RiskDestructive, "sql-drop"},
		{"create or replace table t (id int)", RiskDestructive, "sql-drop"},
		{"alter table t drop column c", RiskDestructive, "sql-drop"},
		{"truncate table t", RiskDestructive, "sql-truncate"},
		{"delete from t", RiskDestructive, "sql-delete-no-where"},
		{"merge into t using s on t.id = s.id when matched then delete", RiskWrite, ""},
		{"grant select on all tables in schema s to role r", RiskDestructive, "sql-privileges"},
		{"revoke role r from user u", RiskDestructive, "sql-privileges"},
		{"create user bob password = 'x'", RiskDestructive, "sql-privileges"},
		{"alter user bob set rsa_public_key = 'x'", RiskDestructive, "sql-privileges"},
		{"create database role db.r", RiskDestructive, "sql-privileges"},
		{"create network policy p allowed_ip_list = ('0.0.0.0/0')", RiskDestructive, "sql-privileges"},
		{"create or replace row access policy p as (a int) returns boolean -> true", RiskDestructive, "sql-privileges"},
		{"alter account set require_storage_integration_for_stage_creation = false", RiskDestructive, "sql-server-config"},
		{"alter warehouse reporting set warehouse_size = 'X6LARGE'", RiskDestructive, "sql-server-config"},
		{"create storage integration s type = external_stage", RiskDestructive, "sql-server-config"},
		{"create external access integration e allowed_network_rules = (r) enabled = true", RiskDestructive, "sql-server-config"},
		{"create resource monitor m with credit_quota = 1", RiskDestructive, "sql-server-config"},
		{"create share s", RiskDestructive, "sql-server-config"},
		{"select system$cancel_query('01b2c3d4-0000-1111-0000-000000000001')", RiskDestructive, "sql-kill"},
		{"select system$abort_session(1234)", RiskDestructive, "sql-kill"},
		{`select "SYSTEM$CANCEL_ALL_QUERIES"(1)`, RiskDestructive, "sql-kill"},
		{"select system$show_oauth_client_secrets('i')", RiskDestructive, "sql-server-config"},
		{"select system$set_return_value('x')", RiskDestructive, "sql-server-config"},
		{"show tables ->> select system$cancel_query('x')", RiskDestructive, "sql-kill"},
		{"call cleanup()", RiskDestructive, "sql-opaque"},
		{"WITH p AS PROCEDURE() RETURNS VARCHAR LANGUAGE SQL AS $$ BEGIN DELETE FROM t; RETURN 'x'; END $$ CALL p()", RiskDestructive, "sql-opaque"},
		{"with p as procedure() returns varchar language sql as 'begin drop table t; return ''x''; end' call p()", RiskDestructive, "sql-opaque"},
		{"SELECT * FROM TABLE(my_proc())", RiskDestructive, "sql-opaque"},
		{"select * from table(admin.ops.cleanup(1))", RiskDestructive, "sql-opaque"},
		{`select * from table("FLATTEN"(input => parse_json('[1]')))`, RiskDestructive, "sql-opaque"},
		{`select * from table("information_schema".query_history())`, RiskDestructive, "sql-opaque"},
		{"execute immediate $$ begin delete from t; end $$", RiskDestructive, "sql-opaque"},
		{"execute task nightly", RiskDestructive, "sql-opaque"},
		{"put file:///tmp/x.csv @my_stage", RiskDestructive, "sql-server-file"},
		{"get @my_stage file:///tmp/", RiskDestructive, "sql-server-file"},
		{"remove @my_stage/old", RiskDestructive, "sql-server-file"},
		{"copy into @my_stage/out from orders", RiskDestructive, "sql-server-file"},
		{"copy into 's3://bucket/out/' from orders credentials = (aws_key_id = 'x')", RiskDestructive, "sql-server-file"},
		{"create stage s url = 's3://bucket/x' credentials = (aws_key_id = 'x')", RiskDestructive, "sql-remote"},
		{"create external function f(a int) returns int api_integration = i as 'https://x'", RiskDestructive, "sql-remote"},
		{"create function f() returns int language python runtime_version = '3.11' handler = 'h' external_access_integrations = (e) as $$x$$", RiskDestructive, "sql-remote"},
	}
	for _, c := range cases {
		p, err := ClassifySQL("snowflake", c.sql)
		if err != nil {
			t.Errorf("%q: %v", c.sql, err)
			continue
		}
		if p.Risk != c.want {
			t.Errorf("%q: risk %s, want %s (rules %v)", c.sql, p.Risk, c.want, p.RuleIDs)
		}
		if c.rule != "" && !slices.Contains(p.RuleIDs, c.rule) {
			t.Errorf("%q: rules %v, want %s", c.sql, p.RuleIDs, c.rule)
		}
		if c.want == RiskRead && p.NeedsWrite() || c.want != RiskRead && !p.NeedsWrite() {
			t.Errorf("%q: NeedsWrite %v", c.sql, p.NeedsWrite())
		}
	}
}

// Nothing can be rolled back: what is not a read goes alone, so a dry
// run only reports it; reads may share a run and return rows.
func TestSnowflakeNoTx(t *testing.T) {
	for sql, want := range map[string]bool{
		"select 1": false, "show tables": false, "describe table t": false, "explain select 1": false, "list @s": false,
		"insert into t values (1)": true, "create table t (a int)": true, "update t set a = 1 where b = 2": true,
		"frobnicate t": true, "show tables ->> delete from t": true,
	} {
		p, err := ClassifySQL("snowflake", sql)
		if err != nil {
			t.Fatalf("%q: %v", sql, err)
		}
		st := p.Statements[0]
		if st.NoTx != want {
			t.Errorf("%q: NoTx %v, want %v", sql, st.NoTx, want)
		}
		if st.Rows == want && !strings.HasPrefix(sql, "show") {
			t.Errorf("%q: Rows %v", sql, st.Rows)
		}
	}
	p, _ := ClassifySQL("snowflake", "frobnicate t")
	if !p.Statements[0].Unknown || !p.NeedsWrite() {
		t.Errorf("an unknown first word needs --write: %+v", p.Statements[0])
	}
	p, _ = ClassifySQL("snowflake", "select 1; select 'a;b'; select $$;$$; show databases")
	if len(p.Statements) != 4 {
		t.Errorf("split: %+v", p.Statements)
	}
	if p, _ := ClassifySQL("snowflake", "call p()"); !p.Statements[0].Rows || !p.Statements[0].NoTx {
		t.Errorf("call: %+v", p.Statements[0])
	}
	if p, _ := ClassifySQL("snowflake", "set x = 1"); p.Statements[0].Rows || p.Statements[0].NoTx {
		t.Errorf("set: %+v", p.Statements[0])
	}
}

func TestClassifySnowflakeRefuses(t *testing.T) {
	for sql, code := range map[string]string{
		"select 1 as naïve":                     "SQL_HIDDEN_CODE",
		"select 1 -- a\rdrop table t":           "SQL_HIDDEN_CODE",
		"select 1 // a\x0bdrop table t":         "SQL_HIDDEN_CODE",
		"select 1 /* a /* b */ drop table t */": "SQL_HIDDEN_CODE",
		"select x$$a$$":                         "SQL_HIDDEN_CODE",
		"select 1$$a$$":                         "SQL_HIDDEN_CODE",
		"begin transaction":                     "SQL_TX_CONTROL",
		"begin":                                 "SQL_TX_CONTROL",
		"commit":                                "SQL_TX_CONTROL",
		"rollback":                              "SQL_TX_CONTROL",
		"start transaction":                     "SQL_TX_CONTROL",
		"begin select 1; end":                   "USAGE",
		"declare x int; begin return 1; end":    "USAGE",
		"select 1 /* never ends":                "USAGE",
		"select 'open":                          "USAGE",
		`select 'a\'`:                           "USAGE",
		`select "a`:                             "USAGE",
		"select $$open":                         "USAGE",
	} {
		_, err := ClassifySQL("snowflake", sql)
		oe, _ := err.(*out.Error)
		if oe == nil || oe.Code != code {
			t.Errorf("%q: %v, want %s", sql, err, code)
		}
	}
	// quoted, the same text is fine
	for _, sql := range []string{`select 'naïve', "straße"`, "select $$naïve$$", "select '$$x'", "select 1 -- naïve\n"} {
		if _, err := ClassifySQL("snowflake", sql); err != nil {
			t.Errorf("%q: %v", sql, err)
		}
	}
}

func TestSnowflakePlaceholders(t *testing.T) {
	for sql, want := range map[string]int{
		"select ?":                    1,
		"select ?, ? from t":          2,
		"select '?', $$?$$, \"?\"":    0,
		"select 1 // ?\n":             0,
		"select $1 from @s where ? 1": 1,
	} {
		n, ok := Placeholders("snowflake", sql)
		if !ok || n != want {
			t.Errorf("%q: %d %v, want %d", sql, n, ok, want)
		}
	}
}

func TestParseSnowflake(t *testing.T) {
	for raw, want := range map[string]SnowflakeConn{
		"snowflake://app@myorg-myacct/ANALYTICS/PUBLIC?warehouse=WH&role=RO": {Account: "myorg-myacct", JWTAccount: "MYORG-MYACCT",
			Host: "myorg-myacct.snowflakecomputing.com", User: "app", Database: "ANALYTICS", Schema: "PUBLIC", Warehouse: "WH", Role: "RO"},
		"snowflake://app@xy12345.eu-central-1/DB": {Account: "xy12345.eu-central-1", JWTAccount: "XY12345",
			Host: "xy12345.eu-central-1.snowflakecomputing.com", User: "app", Database: "DB"},
		"snowflake://app@MyOrg-My_Acct.snowflakecomputing.com:443": {Account: "MyOrg-My_Acct", JWTAccount: "MYORG-MY_ACCT",
			Host: "myorg-my-acct.snowflakecomputing.com", User: "app"},
		"snowflake://app@acct/?ca=secret:proxy-ca": {Account: "acct", JWTAccount: "ACCT", Host: "acct.snowflakecomputing.com", User: "app"},
	} {
		got, err := ParseSnowflakeURL(raw)
		if err != nil || got != want {
			t.Errorf("%s: %+v, %v", raw, got, err)
		}
		tg, err := Parse(raw)
		if err != nil || tg.Kind.Name != "snowflake" || tg.Address != want.Host+":443" || !tg.Secure || tg.User != "app" || tg.Database != want.Database {
			t.Errorf("Parse %s: %+v, %v", raw, tg, err)
		}
	}
	if tg, _ := Parse("snowflake://app@acct/?ca=secret:proxy-ca"); tg.CA != "secret:proxy-ca" {
		t.Errorf("ca: %+v", tg)
	}
	for raw, msg := range map[string]string{
		"snowflake://app@acct:8443/db":               "port 8443",
		"snowflake://acct/db":                        "needs a user",
		"snowflake://app@/db":                        "needs an account",
		"snowflake://app@acct/db/schema/x":           "/DATABASE/SCHEMA",
		"snowflake://app@acct/db?tls=false":          "always HTTPS",
		"snowflake://app@acct/db?authenticator=x":    "unknown snowflake URL option",
		"snowflake://app@acct/db?ca=proxy":           "secret:NAME",
		"snowflake://app@-acct/db":                   "not an account identifier",
		"snowflake://app@acct..x/db":                 "not an account identifier",
		"snowflake://app@acct/db?warehouse=a%0Ab":    "line break",
		"snowflake://app@acct/db?private_key=secret": "unknown snowflake URL option",
	} {
		_, err := Parse(raw)
		if err == nil || !strings.Contains(err.Error()+" "+hintOf(err), msg) {
			t.Errorf("%s: %v, want %q", raw, err, msg)
		}
	}
}

func hintOf(err error) string {
	if oe, ok := err.(*out.Error); ok {
		return oe.Hint
	}
	return ""
}
