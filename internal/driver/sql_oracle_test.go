package driver

import (
	"slices"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestClassifyOracle(t *testing.T) {
	cases := []struct {
		sql  string
		want Risk
		rule string
	}{
		// reads
		{"select id, email from app.users where id = :1", RiskRead, ""},
		{`select "DELETE", "commit" from "DROP"`, RiskRead, ""},
		{"select 'drop table t; commit' from dual", RiskRead, ""},
		{"select q'[it's; delete from t]' from dual", RiskRead, ""},
		{"select nq'{a ' b}' , Q'!x!' from dual", RiskRead, ""},
		{"select 1 from dual -- drop table t\n", RiskRead, ""},
		{"select /*+ full(t) */ * from t", RiskRead, ""},
		{"with x as (select 1 a from dual) select * from x", RiskRead, ""},
		{"select dbms_xplan.format_number(1), dbms_random.value from dual", RiskRead, ""},
		{"select * from t for update", RiskRead, ""},
		{"set role all", RiskRead, ""},
		// writes
		{"update t set a = 1 where id = 2", RiskWrite, ""},
		{"insert into t values (1)", RiskWrite, ""},
		{"merge into t using s on (t.id = s.id) when matched then update set t.a = s.a", RiskWrite, ""},
		{"create table t (id number generated always as identity primary key)", RiskWrite, ""},
		{"create global temporary table t (id number) on commit preserve rows", RiskWrite, ""},
		{"create or replace procedure p as begin delete from t; commit; end;", RiskWrite, ""},
		{"create or replace editionable package body pk as procedure p is begin null; end; end;", RiskWrite, ""},
		{"comment on table t is 'orders'", RiskWrite, ""},
		{"alter session set nls_date_format = 'YYYY-MM-DD'", RiskWrite, ""},
		{"lock table t in exclusive mode", RiskWrite, ""},
		// destructive
		{"begin null; end;", RiskDestructive, "sql-opaque"},
		{"declare x number; begin select 1 into x from dual; end;", RiskDestructive, "sql-opaque"},
		{"call p()", RiskDestructive, "sql-opaque"},
		{"with function f return number is begin return 1; end; select f from dual", RiskDestructive, "sql-opaque"},
		{"select utl_http.request('http://x') from dual", RiskDestructive, "sql-remote"},
		{"select sys.utl_inaddr.get_host_address('x') from dual", RiskDestructive, "sql-remote"},
		{"select dbms_pipe.send_message('x') from dual", RiskDestructive, "sql-opaque"},
		{`select "UTL_HTTP".request('x') from dual`, RiskDestructive, "sql-remote"},
		{"drop table t", RiskDestructive, "sql-drop"},
		{"drop table t purge", RiskDestructive, "sql-drop"},
		{"truncate table t", RiskDestructive, "sql-truncate"},
		{"delete from t", RiskDestructive, "sql-delete-no-where"},
		{"delete t", RiskDestructive, "sql-delete-no-where"},
		{"grant select on t to bob", RiskDestructive, "sql-privileges"},
		{"create user bob identified by \"x\"", RiskDestructive, "sql-privileges"},
		{"alter profile default limit failed_login_attempts 3", RiskDestructive, "sql-privileges"},
		{"alter system set processes = 300 scope = spfile", RiskDestructive, "sql-server-config"},
		{"alter pluggable database pdb1 close", RiskDestructive, "sql-server-config"},
		{"audit select on t", RiskDestructive, "sql-server-config"},
		{"create or replace trigger t after logon on database begin null; end;", RiskDestructive, "sql-server-config"},
		{"select bfilename('D', 'f') from dual", RiskDestructive, "sql-server-file"},
	}
	for _, c := range cases {
		p, err := ClassifySQL("oracle", c.sql)
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

func TestClassifyOracleRefuses(t *testing.T) {
	for sql, code := range map[string]string{
		"commit":                     "SQL_TX_CONTROL",
		"rollback":                   "SQL_TX_CONTROL",
		"savepoint a":                "SQL_TX_CONTROL",
		"set transaction read write": "SQL_TX_CONTROL",
		"begin delete from t where a = 1; commit; end;":           "SQL_TX_CONTROL",
		"begin rollback; end;":                                    "SQL_TX_CONTROL",
		"declare pragma autonomous_transaction; begin null; end;": "SQL_TX_CONTROL",
		"with function f return number is pragma autonomous_transaction; begin delete from t; commit; return 1; end; select f from dual": "SQL_TX_CONTROL",
		"explain plan for select 1 from dual":   "USAGE",
		"select café from t":                    "SQL_HIDDEN_CODE",
		"select 1　from dual":                    "SQL_HIDDEN_CODE",
		"select 1 from dual -- x\rdrop table t": "SQL_HIDDEN_CODE",
		"select 1 from dual -- x\vdrop table t": "SQL_HIDDEN_CODE",
		"select 1 from dual -- x drop table t":  "SQL_HIDDEN_CODE",
		"select q'[x' from dual":                "USAGE",
		"select 'x from dual":                   "USAGE",
		"select 1 /* x from dual":               "USAGE",
	} {
		_, err := ClassifySQL("oracle", sql)
		if e, ok := err.(*out.Error); !ok || e.Code != code {
			t.Errorf("%q: want %s, got %v", sql, code, err)
		}
	}
	// non-ASCII in quotes and comments is fine, and so is \r\n
	if _, err := ClassifySQL("oracle", "select 'café', \"naïve\", q'[ü]' from dual -- é\r\n/* ü */"); err != nil {
		t.Error(err)
	}
}

func TestClassifyOracleStatements(t *testing.T) {
	for sql, want := range map[string][]string{
		"select 1 from dual; select 2 from dual;":                  {"select 1 from dual", "select 2 from dual"},
		"begin\n  null;\nend;\n/\nselect 1 from dual\n/\n":         {"begin\n  null;\nend;", "select 1 from dual"},
		"create procedure p as begin null; end;\n/\nbegin p; end;": {"create procedure p as begin null; end;", "begin p; end;"},
		"begin null; end; select 1 from dual":                      {"begin null; end; select 1 from dual"},
		"select q'[a;b]' from dual; select 4\n/ 2 from dual":       {"select q'[a;b]' from dual", "select 4\n/ 2 from dual"},
		"select nq'#;#' x from dual":                               {"select nq'#;#' x from dual"},
	} {
		p, err := ClassifySQL("oracle", sql)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
			continue
		}
		var got []string
		for _, s := range p.Statements {
			got = append(got, s.SQL)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", sql, got, want)
		}
	}
	for sql, want := range map[string]Statement{
		"select 1 from dual":                             {Rows: true},
		"with x as (select 1 from dual) select * from x": {Rows: true},
		"insert into t values (1) returning id into :1":  {},
		"create table t (id number)":                     {NoTx: true},
		"grant select on t to bob":                       {NoTx: true},
		"truncate table t":                               {NoTx: true},
		"alter session set nls_language = 'GERMAN'":      {},
		"alter system kill session '1,2'":                {NoTx: true, NoRollback: true},
		"begin null; end;":                               {NoRollback: true},
		"call p()":                                       {NoRollback: true},
		"frobnicate t":                                   {NoTx: true, Unknown: true},
		"administer key management set keystore open":    {NoTx: true, Unknown: true},
	} {
		p, err := ClassifySQL("oracle", sql)
		if err != nil {
			t.Fatal(err)
		}
		s := p.Statements[0]
		if s.NoTx != want.NoTx || s.Rows != want.Rows || s.NoRollback != want.NoRollback || s.Unknown != want.Unknown {
			t.Errorf("%q: %+v, want %+v", sql, s, want)
		}
	}
	if p, _ := ClassifySQL("oracle", "describe t"); !p.NeedsWrite() {
		t.Error("an unknown Oracle statement needs --write")
	}
	if !OracleBlock("begin\n null;") || !OracleBlock("create or replace function f return number is") || OracleBlock("select 1 from dual") {
		t.Error("OracleBlock")
	}
}

func TestOraclePlaceholders(t *testing.T) {
	for sql, want := range map[string]int{
		"select * from t where a = :1 and b = :2": 2,
		"select * from t where a = :id":           1,
		"select ':9' from dual -- :8":             0,
		"begin x := 1; end;":                      0,
		"select :1, :1, :2 from dual":             3, // SQL binds by position
		"select * from t where a = :x or b = :x":  2,
		"begin p(:1, :1, :2); end;":               2, // PL/SQL binds by name
	} {
		if n, ok := Placeholders("oracle", sql); !ok || n != want {
			t.Errorf("%q: %d %v, want %d", sql, n, ok, want)
		}
	}
}

func TestParseOracle(t *testing.T) {
	cases := []struct {
		in, where, user, db, tls string
		secure                   bool
	}{
		{"oracle://app@db.internal/ORCLPDB1", "db.internal:1521", "app", "ORCLPDB1", "", false},
		{"oracle://app@db.internal:2484/sales.example.com?tls=true", "db.internal:2484", "app", "sales.example.com", "true", true},
		{"oracle://app@db?sid=ORCL&tls=false", "db:1521", "app", "ORCL", "false", false},
		{"oracle://app@db/X?tls=skip-verify", "db:1521", "app", "X", "skip-verify", true},
		{"oracle://app@db/X?tls=true&ca=secret:corp-ca", "db:1521", "app", "X", "true", true},
	}
	for _, c := range cases {
		tg, err := Parse(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if tg.Kind.Name != "oracle" || tg.Address != c.where || tg.User != c.user || tg.Database != c.db || tg.TLS != c.tls || tg.Secure != c.secure {
			t.Errorf("%s: got %+v", c.in, tg)
		}
	}
	for in, code := range map[string]string{
		"oracle://app:pw@db/X":                          "URL_HAS_PASSWORD",
		"oracle://db/X":                                 "USAGE",
		"oracle://app@/X":                               "USAGE",
		"oracle://app@db":                               "USAGE",
		"oracle://app@db/X?sid=Y":                       "USAGE",
		"oracle://app@db/X)(HOST=evil":                  "USAGE",
		"oracle://app@db/X?tls=maybe":                   "USAGE",
		"oracle://app@db/X?ca=secret:x":                 "USAGE",
		"oracle://app@db/X?tls=skip-verify&ca=secret:x": "USAGE",
		"oracle://app@db/X?tls=true&ca=x":               "USAGE",
		"oracle://app@db/X?wallet=/tmp":                 "USAGE",
		"oracle://app@db:0/X":                           "USAGE",
	} {
		_, err := Parse(in)
		if e, ok := err.(*out.Error); !ok || e.Code != code {
			t.Errorf("%s: want %s, got %v", in, code, err)
		}
	}
}

func TestClassifyOracleCalls(t *testing.T) {
	for sql, rule := range map[string]string{
		// a stored function may commit on its own (AUTONOMOUS_TRANSACTION)
		"select app.purge_logs() from dual":                               "sql-opaque",
		"select purge_logs(1) from dual":                                  "sql-opaque",
		"select pkg.f(1) from dual":                                       "sql-opaque",
		"select sys.f(1) from dual":                                       "sql-opaque",
		`select "PURGE"(1) from dual`:                                     "sql-opaque",
		"select apex_web_service.make_rest_request('x', 'GET') from dual": "sql-opaque",
		"select * from table(pkg.rows_of(1))":                             "sql-opaque",
		"update t set a = app.f(a) where id = 1":                          "sql-opaque",
		"insert into t (a) values (app.f(1))":                             "sql-opaque",
		// across a database link
		"select f@prodlink(1) from dual":   "sql-remote",
		"select * from orders@prodlink":    "sql-remote",
		"delete from t@prodlink where a=1": "sql-remote",
		// inline external tables read server files, a preprocessor runs a program
		"select * from external ((c varchar2(100)) type oracle_loader default directory d access parameters (records delimited by newline preprocessor exec_dir:'run.sh') location ('x.txt')) t": "sql-program",
		"select * from external ((c varchar2(100)) default directory d location ('x.txt')) t":                                                                                                    "sql-server-file",
		"select * from ext_t external modify (location ('other.txt'))":                                                                                                                           "sql-server-file",
		"select * from external ((c number) type oracle_loader default directory d access parameters using clob (select p from q) location ('x')) t":                                             "sql-program",
	} {
		p, err := ClassifySQL("oracle", sql)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
			continue
		}
		if p.Risk != RiskDestructive || !slices.Contains(p.RuleIDs, rule) || !p.Statements[0].NoRollback {
			t.Errorf("%q: %s %v, want %s", sql, p.Risk, p.RuleIDs, rule)
		}
	}
	// Oracle's own functions, keywords and type names before ( are no calls
	for _, sql := range []string{
		"select count(*), nvl(a, 0), to_char(sysdate, 'YYYY'), decode(a, 1, 'x') from t where a in (1, 2) and exists (select 1 from u)",
		"select row_number() over (partition by a order by b), listagg(c, ',') within group (order by c) from t group by rollup (a, b)",
		"with x (a, b) as (select 1, 2 from dual) select * from x",
		"with x as (select 1 a from dual) select * from x cross join lateral (select 1 from dual)",
		"select cast(a as number(10, 2)), cast(b as varchar2(20)), interval '1' day(2) to second(3) from t",
		"select * from json_table(doc, '$' columns (a number path '$.a')) j",
		"select * from t pivot (sum(a) for b in (1, 2))",
		"select * from t sample (10) seed (1) where (a, b) in ((1, 2))",
		"select * from t1 join t2 using (id) where not (a = 1) or (b = 2)",
		"select case when (a > 1) then (1) else (2) end from t",
		"select dbms_xplan.format_number(1), sys.dbms_random.value from dual",
		"select * from t as of timestamp (systimestamp - interval '1' hour)",
	} {
		p, err := ClassifySQL("oracle", sql)
		if err != nil || p.Risk != RiskRead || len(p.RuleIDs) != 0 {
			t.Errorf("%q: %s %v %v, want read", sql, p.Risk, p.RuleIDs, err)
		}
	}
	for _, sql := range []string{
		"insert into t (a, b) values (1, 2)",
		"insert into app.t (a) select a from u",
		"merge into t using (select 1 id from dual) s on (t.id = s.id) when not matched then insert (id) values (s.id)",
		"update t set (a, b) = (select 1, 2 from dual) where id = 1",
		"create table t (id number(10), c varchar2(20))", // DDL: needs --write anyway
		"create index i on t (c)",
	} {
		p, err := ClassifySQL("oracle", sql)
		if err != nil || p.Risk != RiskWrite || len(p.RuleIDs) != 0 {
			t.Errorf("%q: %s %v %v, want write", sql, p.Risk, p.RuleIDs, err)
		}
	}
}
