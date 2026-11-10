package driver

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestClassifyBigQuery(t *testing.T) {
	cases := []struct {
		sql  string
		want Risk
		rule string
	}{
		// reads
		{"select * from shop.orders where id = ?", RiskRead, ""},
		{"select * from `my-project.shop.orders` limit 10", RiskRead, ""},
		{"select * from my-project.shop.orders", RiskRead, ""},
		{`select 'it\'s; drop table t' as x`, RiskRead, ""},
		{`select "it's; drop table t" as x`, RiskRead, ""},
		{`select 'a\\'; select 1`, RiskRead, ""},
		{"select '''a\n'; drop table t''' as x", RiskRead, ""},
		{`select """it's "quoted"; drop table t""" as x`, RiskRead, ""},
		{`select r'a\d+' as re, b'\x00' as by, rb"x" as raw`, RiskRead, ""},
		{"select `a``b; drop table t` from t", RiskRead, ""},
		{"select `drop` from t", RiskRead, ""},
		{"select 1 # it's; drop table t\n as x", RiskRead, ""},
		{"select 1 -- it's; drop table t\r\n as x", RiskRead, ""},
		{"select 1 /* it's; drop table t */ as x", RiskRead, ""},
		{"with x as (select 1 as a) select * from x", RiskRead, ""},
		{"(select 1) union all (select 2)", RiskRead, ""},
		{"from shop.orders |> where total > 10 |> aggregate count(*)", RiskRead, ""},
		{"select * from `region-eu`.INFORMATION_SCHEMA.JOBS where state != 'DONE'", RiskRead, ""},
		{"select json_value(payload, '$.a') from events", RiskRead, ""},
		{"select @@project_id, @x", RiskRead, ""},
		// writes: sent alone, a dry run only checks them
		{"insert into shop.t (id) values (1)", RiskWrite, ""},
		{"update shop.t set v = 1 where id = 2", RiskWrite, ""},
		{"delete from shop.t where id = 1", RiskWrite, ""},
		{"merge shop.t t using shop.s s on t.id = s.id when matched then update set v = s.v", RiskWrite, ""},
		{"merge shop.t t using shop.s s on t.id = s.id when matched then delete", RiskWrite, ""},
		{"MERGE shop.orders t USING (SELECT 1 AS id LIMIT 0) s ON FALSE WHEN NOT MATCHED BY SOURCE THEN DELETE", RiskDestructive, "sql-delete-no-where"},
		{"merge shop.orders t using shop.s s on t.id = s.id when not matched by source then update set amount = 0", RiskDestructive, "sql-update-no-where"},
		{"create table shop.t (id int64) partition by date(ts) cluster by id", RiskWrite, ""},
		{"create table if not exists shop.policy (id int64)", RiskWrite, ""},
		{"create temp function f(x int64) as (x + 1)", RiskWrite, ""},
		{"create materialized view shop.mv as select 1 as a", RiskWrite, ""},
		{"create schema logs options (location = 'EU')", RiskWrite, ""},
		{"alter table shop.t add column c string", RiskWrite, ""},
		{"alter table shop.t set options (description = 'x')", RiskWrite, ""},
		{"undrop schema logs", RiskWrite, ""},
		{"load data into shop.t from files (format = 'CSV', uris = ['gs://b/x.csv'])", RiskWrite, ""},
		{"assert (select count(*) from t) > 0 as 'empty'", RiskWrite, ""},
		{"frobnicate t", RiskWrite, ""},
		// destructive
		{"drop table shop.t", RiskDestructive, "sql-drop"},
		{"drop schema logs cascade", RiskDestructive, "sql-drop"},
		{"create or replace table shop.t as select 1 as a", RiskDestructive, "sql-drop"},
		{"alter table shop.t drop column c", RiskDestructive, "sql-drop"},
		{"truncate table shop.t", RiskDestructive, "sql-truncate"},
		{"load data overwrite shop.t from files (format = 'CSV', uris = ['gs://b/x.csv'])", RiskDestructive, "sql-truncate"},
		{"delete from shop.t", RiskDestructive, "sql-delete-no-where"},
		{"grant `roles/bigquery.dataViewer` on schema shop to 'user:a@example.com'", RiskDestructive, "sql-privileges"},
		{"revoke `roles/bigquery.dataViewer` on schema shop from 'user:a@example.com'", RiskDestructive, "sql-privileges"},
		{"create row access policy p on shop.t grant to ('user:a@example.com') filter using (true)", RiskDestructive, "sql-privileges"},
		{"drop all row access policies on shop.t", RiskDestructive, "sql-privileges"},
		{"create capacity `admin.region-us.c1` options (slot_count = 100, plan = 'ANNUAL')", RiskDestructive, "sql-server-config"},
		{"create reservation `admin.region-us.r1` options (slot_capacity = 100)", RiskDestructive, "sql-server-config"},
		{"create assignment `admin.region-us.r1.a1` options (assignee = 'projects/p', job_type = 'QUERY')", RiskDestructive, "sql-server-config"},
		{"alter project p set options (`region-us.default_time_zone` = 'UTC')", RiskDestructive, "sql-server-config"},
		{"alter organization set options (`region-us.default_kms_key_name` = 'k')", RiskDestructive, "sql-server-config"},
		{"export data options (uri = 'gs://b/x/*.csv', format = 'CSV') as select * from shop.t", RiskDestructive, "sql-remote"},
		{"select * from external_query('p.eu.conn', 'select * from users')", RiskDestructive, "sql-remote"},
		{"create function shop.f(x int64) returns int64 remote with connection `p.eu.c` options (endpoint = 'https://x')", RiskDestructive, "sql-remote"},
		{"call shop.cleanup()", RiskDestructive, "sql-opaque"},
		{"call bq.abort_session('s1')", RiskDestructive, "sql-kill"},
		{"execute immediate 'delete from shop.t where true'", RiskDestructive, "sql-opaque"},
	}
	for _, c := range cases {
		p, err := ClassifySQL("bigquery", c.sql)
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

// Each statement is a job of its own: what is not a read goes alone, so a
// dry run only checks it; reads may share a run and return rows.
func TestBigQueryNoTx(t *testing.T) {
	for sql, want := range map[string]bool{
		"select 1": false, "with x as (select 1) select * from x": false, "from t |> limit 1": false,
		"insert into t values (1)": true, "create table t (a int64)": true, "update t set a = 1 where b = 2": true, "frobnicate t": true,
	} {
		p, err := ClassifySQL("bigquery", sql)
		if err != nil {
			t.Fatalf("%q: %v", sql, err)
		}
		st := p.Statements[0]
		if st.NoTx != want || st.Rows == want {
			t.Errorf("%q: NoTx %v, Rows %v", sql, st.NoTx, st.Rows)
		}
	}
	p, _ := ClassifySQL("bigquery", "select 1; select 'a;b'; select \"a;b\"; select `a;b` from t; select '''a;b'''")
	if len(p.Statements) != 5 {
		t.Errorf("split: %+v", p.Statements)
	}
	if p, _ := ClassifySQL("bigquery", "call p()"); !p.Statements[0].Rows || !p.Statements[0].NoTx {
		t.Errorf("call: %+v", p.Statements[0])
	}
	// db explain is a dry run: a write is planned, not run
	p, _ = ClassifySQL("bigquery", "delete from t where id = 1")
	if q := PlanOnly(p); q.Risk != RiskRead || q.Statements[0].NoTx {
		t.Errorf("plan only: %+v", q)
	}
	p, _ = ClassifySQL("bigquery", "select * from external_query('c', 'select 1')")
	if q := PlanOnly(p); q.Risk != RiskDestructive {
		t.Errorf("plan only keeps what reaches elsewhere: %+v", q)
	}
}

func TestClassifyBigQueryRefuses(t *testing.T) {
	for sql, code := range map[string]string{
		"select 1 as naïve":                     "SQL_HIDDEN_CODE",
		"select 1 -- a\rdrop table t":           "SQL_HIDDEN_CODE",
		"select 1 # a\x0bdrop table t":          "SQL_HIDDEN_CODE",
		"select 1 /* a /* b */ drop table t */": "SQL_HIDDEN_CODE",
		`select r'a\'; drop table t; '`:         "SQL_HIDDEN_CODE",
		"begin transaction":                     "SQL_TX_CONTROL",
		"begin":                                 "SQL_TX_CONTROL",
		"commit transaction":                    "SQL_TX_CONTROL",
		"rollback":                              "SQL_TX_CONTROL",
		"begin select 1; end":                   "USAGE",
		"declare x int64 default 1":             "USAGE",
		"set x = 5":                             "USAGE",
		"if true then select 1; end if":         "USAGE",
		"loop select 1; end loop":               "USAGE",
		"select 1 /* never ends":                "USAGE",
		"select 'open":                          "USAGE",
		`select 'a\'`:                           "USAGE",
		`select "a`:                             "USAGE",
		"select '''open":                        "USAGE",
		"select `open":                          "USAGE",
	} {
		_, err := ClassifySQL("bigquery", sql)
		oe, _ := err.(*out.Error)
		if oe == nil || oe.Code != code {
			t.Errorf("%q: %v, want %s", sql, err, code)
		}
	}
	// quoted, the same text is fine
	for _, sql := range []string{`select 'naïve', "straße", ` + "`größe`", "select 1 -- naïve\n", "select 1 # naïve\n", `select r'a\b'`} {
		if _, err := ClassifySQL("bigquery", sql); err != nil {
			t.Errorf("%q: %v", sql, err)
		}
	}
}

func TestBigQueryPlaceholders(t *testing.T) {
	for sql, want := range map[string]int{
		"select ?":                               1,
		"select ?, ? from t":                     2,
		"select '?', \"?\", `?`, '''?''' from t": 0,
		"select 1 # ?\n":                         0,
		"select 1 -- ?\n, ?":                     1,
	} {
		n, ok := Placeholders("bigquery", sql)
		if !ok || n != want {
			t.Errorf("%q: %d %v, want %d", sql, n, ok, want)
		}
	}
}

func TestParseBigQuery(t *testing.T) {
	for raw, want := range map[string]BigQueryConn{
		"bigquery://my-project":                                           {Project: "my-project", Endpoint: BigQueryEndpoint},
		"bigquery://my-project/shop?location=EU":                          {Project: "my-project", Dataset: "shop", Location: "EU", Endpoint: BigQueryEndpoint},
		"bigquery://my-project/shop?endpoint=http://127.0.0.1:9050/":      {Project: "my-project", Dataset: "shop", Endpoint: "http://127.0.0.1:9050"},
		"bigquery://my-project/?ca=secret:proxy-ca&location=europe-west1": {Project: "my-project", Location: "europe-west1", Endpoint: BigQueryEndpoint},
	} {
		got, err := ParseBigQueryURL(raw)
		if err != nil || got != want {
			t.Errorf("%s: %+v, %v", raw, got, err)
		}
	}
	tg, err := Parse("bigquery://my-project/shop?location=EU&ca=secret:proxy-ca")
	if err != nil || tg.Kind.Name != "bigquery" || tg.Address != "bigquery.googleapis.com:443" || !tg.Secure || tg.Database != "shop" || tg.CA != "secret:proxy-ca" {
		t.Errorf("Parse: %+v, %v", tg, err)
	}
	if tg, err := Parse("bigquery://my-project?endpoint=http://localhost:9050"); err != nil || tg.Secure || tg.Address != "localhost:9050" {
		t.Errorf("emulator: %+v, %v", tg, err)
	}
	for raw, msg := range map[string]string{
		"bigquery://app@my-project":                           "has no user",
		"bigquery://My_Project":                               "not a project ID",
		"bigquery://my-project:443":                           "not a project ID",
		"bigquery://abc":                                      "not a project ID",
		"bigquery://my-project/shop/orders":                   "one dataset",
		"bigquery://my-project?tls=false":                     "always HTTPS",
		"bigquery://my-project?credentials=x":                 "unknown bigquery URL option",
		"bigquery://my-project?location=e%20u":                "not a location",
		"bigquery://my-project?ca=proxy":                      "secret:NAME",
		"bigquery://my-project?endpoint=ftp://x":              "endpoint must be a URL",
		"bigquery://my-project?endpoint=http://x&ca=secret:c": "https:// endpoint",
	} {
		_, err := Parse(raw)
		if err == nil || !strings.Contains(err.Error()+" "+hintOf(err), msg) {
			t.Errorf("%s: %v, want %q", raw, err, msg)
		}
	}
}
