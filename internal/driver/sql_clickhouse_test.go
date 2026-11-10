package driver

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestClassifyClickHouse(t *testing.T) {
	cases := []struct {
		sql  string
		want Risk
		rule string
	}{
		// reads
		{"select count() from hits where CounterID = {p1:UInt32}", RiskRead, ""},
		{"SELECT `drop`, \"delete\" FROM `table`", RiskRead, ""},
		{`select 'it\'s; drop table t' as x`, RiskRead, ""},
		{"select '; drop table t ''' as x", RiskRead, ""},
		{"select 1 /* a /* nested; drop table t */ still; drop */ as x", RiskRead, ""},
		{"select 1 # drop table t\n as x", RiskRead, ""},
		{"select 1 -- drop table t\n", RiskRead, ""},
		{"with x as (select 1 as a) select * from x", RiskRead, ""},
		{"show tables from default", RiskRead, ""},
		{"show create table default.t", RiskRead, ""},
		{"describe table default.t", RiskRead, ""},
		{"exists table default.t", RiskRead, ""},
		{"explain indexes = 1 select * from t where a = 1", RiskRead, ""},
		{"select * from system.parts where active", RiskRead, ""},
		{"select dictGet('d', 'v', 1), merge('db', '^t'), numbers(3)", RiskRead, ""},
		{"select domain(url) from visits", RiskRead, ""},
		// writes: sent alone, a dry run only reports them
		{"insert into t values (1, 'a')", RiskWrite, ""},
		{"insert into t select * from t2", RiskWrite, ""},
		{"create table t (a UInt64) engine = MergeTree order by a", RiskWrite, ""},
		{"alter table t add column b String", RiskWrite, ""},
		{"alter table t delete where a = 1", RiskWrite, ""},
		{"alter table t update b = 'x' where a = 1", RiskWrite, ""},
		{"delete from t where a = 1", RiskWrite, ""},
		{"optimize table t final", RiskWrite, ""},
		{"rename table a to b", RiskWrite, ""},
		{"exchange tables a and b", RiskWrite, ""},
		{"attach table t", RiskWrite, ""},
		{"create function plus1 as (x) -> x + 1", RiskWrite, ""},
		// destructive
		{"drop table t", RiskDestructive, "sql-drop"},
		{"truncate table t", RiskDestructive, "sql-truncate"},
		{"detach table t", RiskDestructive, "sql-drop"},
		{"alter table t drop partition 202401", RiskDestructive, "sql-drop"},
		{"alter table t clear column b in partition 202401", RiskDestructive, "sql-drop"},
		{"alter table t detach partition 202401", RiskDestructive, "sql-drop"},
		{"alter table t freeze", RiskDestructive, "sql-server-file"},
		{"kill query where query_id = 'x'", RiskDestructive, "sql-kill"},
		{"system shutdown", RiskDestructive, "sql-kill"},
		{"system drop dns cache", RiskDestructive, "sql-server-config"},
		{"system reload config", RiskDestructive, "sql-server-config"},
		{"grant select on db.* to bob", RiskDestructive, "sql-privileges"},
		{"revoke select on db.* from bob", RiskDestructive, "sql-privileges"},
		{"create user bob identified with sha256_password by 'x'", RiskDestructive, "sql-privileges"},
		{"create or replace role readers", RiskDestructive, "sql-privileges"},
		{"alter settings profile p settings max_threads = 1", RiskDestructive, "sql-privileges"},
		{"create row policy p on t using a = 1 to bob", RiskDestructive, "sql-privileges"},
		{"create quota q for interval 1 hour max queries = 10 to bob", RiskDestructive, "sql-privileges"},
		{"move user bob to local_directory", RiskDestructive, "sql-privileges"},
		{"create named collection c as url = 'http://x'", RiskDestructive, "sql-server-config"},
		{"backup table t to Disk('backups', 't.zip')", RiskDestructive, "sql-server-file"},
		{"restore table t from Disk('backups', 't.zip')", RiskDestructive, "sql-server-file"},
		{"select * from url('http://169.254.169.254/latest', CSV, 'a String')", RiskDestructive, "sql-remote"},
		{"select * from s3('https://bucket.s3.amazonaws.com/x.csv')", RiskDestructive, "sql-remote"},
		{"select * from s3Cluster('c', 'https://b/x.csv')", RiskDestructive, "sql-remote"},
		{"select * from remote('10.0.0.5:9000', db.t, 'u', 'p')", RiskDestructive, "sql-remote"},
		{"select * from mysql('db:3306', 'shop', 'orders', 'u', 'p')", RiskDestructive, "sql-remote"},
		{"select * from postgresql('db:5432', 'app', 'users', 'u', 'p')", RiskDestructive, "sql-remote"},
		{"select * from icebergS3('https://b/t')", RiskDestructive, "sql-remote"},
		{"select * from azureBlobStorage('x', 'c', 'f')", RiskDestructive, "sql-remote"},
		{"select * from `url`('http://x', CSV, 'a String')", RiskDestructive, "sql-remote"},
		{"select * from file('/etc/passwd', LineAsString)", RiskDestructive, "sql-server-file"},
		{"select * from sqlite('/var/lib/app.db', 't')", RiskDestructive, "sql-server-file"},
		{"select * from executable('script.sh', TSV, 'a String')", RiskDestructive, "sql-program"},
		{"describe table url('http://x', CSV)", RiskDestructive, "sql-remote"},
		{"explain select * from url('http://x', CSV, 'a String')", RiskDestructive, "sql-remote"},
		{"insert into function url('http://x', CSV, 'a String') values ('a')", RiskDestructive, "sql-remote"},
		{"insert into function file('out.csv') select 1", RiskDestructive, "sql-server-file"},
		{"create table t (a String) engine = URL('http://x', CSV)", RiskDestructive, "sql-remote"},
		{"create table t (a String) engine = Kafka settings kafka_broker_list = 'k:9092'", RiskDestructive, "sql-remote"},
		{"create database d engine = Filesystem('/var/lib/clickhouse/user_files')", RiskDestructive, "sql-server-file"},
		{"create database d engine = Filesystem", RiskDestructive, "sql-server-file"},
		{"create database d engine = S3", RiskDestructive, "sql-remote"},
		{"create dictionary d (k String, v String) primary key k source(YAMLRegExpTree(path '/etc/x.yaml')) layout(regexp_tree) lifetime(0)", RiskDestructive, "sql-server-file"},
		{"create or replace table orders (a UInt8) engine = Memory", RiskDestructive, "sql-drop"},
		{"create or replace temporary table orders (a UInt8) engine = Memory", RiskDestructive, "sql-drop"},
		{"replace table orders (a UInt8) engine = Memory", RiskDestructive, "sql-drop"},
		{"create or replace view v as select 1", RiskWrite, ""},
		{"alter table events modify ttl ts + interval 0 day", RiskDestructive, "sql-drop"},
		{"alter table events materialize ttl", RiskDestructive, "sql-drop"},
		{"alter table events modify column v String ttl ts + interval 1 day", RiskDestructive, "sql-drop"},
		{"alter table events remove ttl", RiskWrite, ""},
		{"alter table events replace partition 202401 from scratch", RiskDestructive, "sql-drop"},
		{"alter table events move partition 202401 to table archive", RiskDestructive, "sql-drop"},
		{"alter table events move partition 202401 to disk 'cold'", RiskWrite, ""},
		{"create table t (a String) engine = Kafka('k:9092', 'topic', 'g', 'JSONEachRow')", RiskDestructive, "sql-remote"},
		{"create database m engine = MySQL('db:3306', 'shop', 'u', 'p')", RiskDestructive, "sql-remote"},
		{"create dictionary d (id UInt64, v String) primary key id source(HTTP(url 'http://x' format 'TSV')) layout(flat()) lifetime(300)", RiskDestructive, "sql-remote"},
		{"create dictionary d (id UInt64) primary key id source(EXECUTABLE(command 'cat x' format 'TSV')) layout(flat()) lifetime(0)", RiskDestructive, "sql-program"},
		{"select 1 into outfile 'x.csv'", RiskDestructive, "sql-server-file"},
	}
	for _, c := range cases {
		p, err := ClassifySQL("clickhouse", c.sql)
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

// ClickHouse has no transactions: what is not a read goes alone, so a
// dry run only reports it; reads may share a run and return rows.
func TestClickHouseNoTx(t *testing.T) {
	for sql, want := range map[string]bool{
		"select 1": false, "show tables": false, "describe t": false, "explain select 1": false, "exists t": false,
		"insert into t values (1)": true, "alter table t delete where a = 1": true, "create table t (a Int8) engine = Memory": true,
		"optimize table t": true, "frobnicate t": true,
	} {
		p, err := ClassifySQL("clickhouse", sql)
		if err != nil {
			t.Fatalf("%q: %v", sql, err)
		}
		st := p.Statements[0]
		if st.NoTx != want {
			t.Errorf("%q: NoTx %v, want %v", sql, st.NoTx, want)
		}
		if st.Rows == want {
			t.Errorf("%q: Rows %v", sql, st.Rows)
		}
	}
	p, _ := ClassifySQL("clickhouse", "frobnicate t")
	if !p.Statements[0].Unknown || !p.NeedsWrite() {
		t.Errorf("an unknown first word needs --write: %+v", p.Statements[0])
	}
	p, _ = ClassifySQL("clickhouse", "select 1; select 'a;b'; show databases")
	if len(p.Statements) != 3 {
		t.Errorf("split: %+v", p.Statements)
	}
}

func TestClassifyClickHouseRefuses(t *testing.T) {
	for sql, code := range map[string]string{
		"select $$x$$":                       "SQL_HIDDEN_CODE",
		"select $tag$; drop table t$tag$":    "SQL_HIDDEN_CODE",
		"select 1 as naïve":                  "SQL_HIDDEN_CODE",
		"select 1 drop table t":              "SQL_HIDDEN_CODE",
		"begin transaction":                  "SQL_TX_CONTROL",
		"commit":                             "SQL_TX_CONTROL",
		"rollback":                           "SQL_TX_CONTROL",
		"select 1 /* never ends":             "USAGE",
		"select 'open":                       "USAGE",
		"select `a\\`":                       "USAGE",
		"select `a\\`; drop table t` from x": "SQL_HIDDEN_CODE",
		"select * from `\\x75rl`('http://169.254.169.254/latest/meta-data/', RawBLOB)": "SQL_HIDDEN_CODE",
		`select * from "\x66ile"('/etc/passwd', LineAsString)`:                         "SQL_HIDDEN_CODE",
		"insert into function `\\x66ile`('out.csv') select 1":                          "SQL_HIDDEN_CODE",
		"select 1 /* a /* b */ drop t":                                                 "USAGE",
	} {
		_, err := ClassifySQL("clickhouse", sql)
		var oe *out.Error
		if e, ok := err.(*out.Error); ok {
			oe = e
		}
		if oe == nil || oe.Code != code {
			t.Errorf("%q: %v, want %s", sql, err, code)
		}
	}
	// quoted, the same text is fine
	for _, sql := range []string{"select 'naïve', `straße`", "select '$$x$$'", "select 'a' as `$x`"} {
		if _, err := ClassifySQL("clickhouse", sql); err != nil {
			t.Errorf("%q: %v", sql, err)
		}
	}
}

func TestClickHousePlaceholders(t *testing.T) {
	for sql, want := range map[string]int{
		"select {p1:String}":                           1,
		"select {p1:String}, {p2:UInt64}, {p1:String}": 2,
		"select '{p9:String}'":                         0,
		"select map('a', 1)":                           0,
	} {
		n, ok := Placeholders("clickhouse", sql)
		if !ok || n != want {
			t.Errorf("%q: %d %v, want %d", sql, n, ok, want)
		}
	}
	if _, ok := Placeholders("clickhouse", "select {id:UInt64}"); ok {
		t.Error("a named parameter cannot be counted")
	}
	if !strings.Contains(ClickHouseVerified("clickhouse://a@h:8123/db"), "h:8443/db?tls=true") {
		t.Error(ClickHouseVerified("clickhouse://a@h:8123/db"))
	}
}
