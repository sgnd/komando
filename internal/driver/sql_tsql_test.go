package driver

import (
	"slices"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestClassifyTSQL(t *testing.T) {
	cases := []struct {
		sql  string
		want Risk
		rule string // a rule that must be reported ("" = none)
	}{
		// reads
		{"select id, email from dbo.users where id = 1", RiskRead, ""},
		{"SELECT [drop], [a]]b] FROM [delete]", RiskRead, ""},
		{`select "update" from t`, RiskRead, ""},
		{"select 'DROP TABLE x; COMMIT', N'delete'", RiskRead, ""},
		{"select 1 -- drop table t\n", RiskRead, ""},
		{"select /* /* nested */ drop table t */ 1", RiskRead, ""},
		{"with x as (select 1 as a) select * from x", RiskRead, ""},
		{"select case when a = 1 then 'x' end from t", RiskRead, ""},
		{"declare @x int = 1", RiskRead, ""},
		{"print 'hello'", RiskRead, ""},
		{"set nocount on", RiskRead, ""},
		{"select top (10) * from t with (nolock) option (recompile)", RiskRead, ""},
		{"select 0x1F, 0xBEEF, 1.5e3, 2E-4, 1., .5 from t", RiskRead, ""},
		{"select send, receive, get, move from t", RiskRead, ""},
		// writes
		{"update t set a = 1 where id = 2", RiskWrite, ""},
		{"insert into t values (1)", RiskWrite, ""},
		{"create table t (id int identity primary key)", RiskWrite, ""},
		{"select * into #tmp from t", RiskWrite, ""},
		{"update statistics dbo.orders", RiskWrite, ""},
		{"select next value for dbo.seq", RiskWrite, ""},
		{"create procedure p as begin delete from t; commit; exec xp_cmdshell 'dir'; end", RiskWrite, ""},
		{"create or alter function f() returns int as begin return 1; end", RiskWrite, ""},
		{"waitfor delay '00:00:01'", RiskWrite, ""},
		// destructive: a hidden second statement, a procedure, a rule
		{"select 1 delete from t", RiskDestructive, "sql-delete-no-where"},
		{"select 1DELETE from t", RiskDestructive, "sql-delete-no-where"},
		{"select 1 drop table t", RiskDestructive, "sql-drop"},
		// SQL Server ends a number literal where its form ends: 1e, 1.e and 0x are whole literals
		{"select 1eDROP TABLE t", RiskDestructive, "sql-drop"},
		{"select 1.eDROP TABLE t", RiskDestructive, "sql-drop"},
		{"select 1e5drop table t", RiskDestructive, "sql-drop"},
		{"select 1.5e+3drop table t", RiskDestructive, "sql-drop"},
		{"select 0xTRUNCATE TABLE t", RiskDestructive, "sql-truncate"},
		{"select 0x1Fshutdown", RiskDestructive, "sql-kill"},
		{"select 1eUPDATE t set a = 1", RiskDestructive, "sql-update-no-where"},
		{"select 0xUPDATE t set a = 1 where b = 2", RiskWrite, ""},
		{"select 0xNEXT VALUE FOR s", RiskWrite, ""},
		{"select 1eWAITFOR DELAY '01:00'", RiskWrite, ""},
		// Service Broker statements change a queue wherever they stand
		{"select 1 receive * from dbo.q", RiskWrite, ""},
		{"select 1 receive top (1) * from dbo.q", RiskWrite, ""},
		{"select 1 send on conversation @h (N'x')", RiskWrite, ""},
		{"select 1 end conversation @h", RiskWrite, ""},
		{"select 1 move conversation @h to @g", RiskWrite, ""},
		{"select 1 get conversation group @g from dbo.q", RiskWrite, ""},
		{"select 1 --x\vdrop table t", RiskDestructive, "sql-drop"},
		{"select 1 --x\fdrop table t", RiskDestructive, "sql-drop"},
		{"sp_who", RiskDestructive, "sql-opaque"},
		{"explain select 1", RiskDestructive, "sql-opaque"},
		{"exec sp_who2", RiskDestructive, "sql-opaque"},
		{"select 1 exec xp_cmdshell 'dir'", RiskDestructive, "sql-opaque"},
		{"insert into t exec dbo.load", RiskDestructive, "sql-opaque"},
		{"select {call dbo.p}", RiskDestructive, "sql-opaque"},
		{"kill 53", RiskDestructive, "sql-kill"},
		{"select 1 shutdown", RiskDestructive, "sql-kill"},
		{"create login bob with password = 'x'", RiskDestructive, "sql-privileges"},
		{"alter role db_owner add member bob", RiskDestructive, "sql-privileges"},
		{"alter server role sysadmin add member bob", RiskDestructive, "sql-privileges"},
		{"deny select on t to bob", RiskDestructive, "sql-privileges"},
		{"grant execute on dbo.p to bob", RiskDestructive, "sql-privileges"},
		{"backup database sales to disk = N'/tmp/s.bak'", RiskDestructive, "sql-server-file"},
		{"select * from openrowset(bulk '/etc/passwd', single_clob) x", RiskDestructive, "sql-server-file"},
		{"bulk insert t from '/tmp/x.csv'", RiskDestructive, "sql-server-file"},
		{"select * from openquery(srv, 'select 1')", RiskDestructive, "sql-remote"},
		{"dbcc freeproccache", RiskDestructive, "sql-server-config"},
		{"alter database sales set single_user with rollback immediate", RiskDestructive, "sql-server-config"},
		{"create trigger t on all server for logon as rollback", RiskDestructive, "sql-server-config"},
		{"truncate table t", RiskDestructive, "sql-truncate"},
	}
	for _, c := range cases {
		p, err := ClassifySQL("sqlserver", c.sql)
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

func TestClassifyTSQLRefuses(t *testing.T) {
	for sql, code := range map[string]string{
		"select 1 commit":                          "SQL_TX_CONTROL",
		"begin tran":                               "SQL_TX_CONTROL",
		"select 1 rollback":                        "SQL_TX_CONTROL",
		"select 1eCOMMIT":                          "SQL_TX_CONTROL",
		"select 0xROLLBACK":                        "SQL_TX_CONTROL",
		"select 1.e-commit":                        "SQL_TX_CONTROL",
		"save transaction x":                       "SQL_TX_CONTROL",
		"if 1 = 1 begin select 1 end":              "SQL_TX_CONTROL",
		"set implicit_transactions on":             "SQL_TX_CONTROL",
		"select 1 set ansi_defaults on":            "SQL_TX_CONTROL",
		"set transaction isolation level snapshot": "SQL_TX_CONTROL",
		"select 1 set showplan_text off":           "SQL_TX_CONTROL",
		"set noexec off":                           "SQL_TX_CONTROL",
		"select café from t":                       "SQL_HIDDEN_CODE",
		"select 1　drop table t":                    "SQL_HIDDEN_CODE",
		"select 1 -- x drop table t":               "SQL_HIDDEN_CODE",
		"select 1 -- x\u0085drop table t":          "SQL_HIDDEN_CODE",
		"select /* /* */ 1":                        "USAGE",
		"select [unterminated":                     "USAGE",
	} {
		_, err := ClassifySQL("sqlserver", sql)
		if e, ok := err.(*out.Error); !ok || e.Code != code {
			t.Errorf("%q: want %s, got %v", sql, code, err)
		}
	}
	// non-ASCII inside quotes and comments is fine
	if _, err := ClassifySQL("sqlserver", "select N'café', [naïve] from t -- é\n/* ü */"); err != nil {
		t.Error(err)
	}
}

func TestClassifyTSQLStatements(t *testing.T) {
	p, err := ClassifySQL("sqlserver", "create procedure p as select 1; select 2")
	if err != nil || len(p.Statements) != 1 {
		t.Fatalf("a procedure body runs to the end: %+v %v", p.Statements, err)
	}
	p, _ = ClassifySQL("sqlserver", "select 1; update t set a = 1 where b = 2")
	if len(p.Statements) != 2 {
		t.Errorf("statements: %+v", p.Statements)
	}
	for sql, want := range map[string]Statement{
		"backup database x to disk = 'y'":             {NoTx: true, NoRollback: true},
		"create database x":                           {NoTx: true},
		"alter database x set read_only":              {NoTx: true, NoRollback: true},
		"exec sp_who":                                 {Rows: true, NoRollback: true},
		"sp_who":                                      {Rows: true, NoRollback: true, Unknown: true},
		"insert into t output inserted.id values (1)": {Rows: true},
		"select 1":                                    {Rows: true},
		"update t set a = 1 where id = 1":             {},
		"create table t (id int)":                     {},
		"kill 52":                                     {NoRollback: true},
	} {
		p, err := ClassifySQL("sqlserver", sql)
		if err != nil {
			t.Fatal(err)
		}
		s := p.Statements[0]
		if s.NoTx != want.NoTx || s.Rows != want.Rows || s.NoRollback != want.NoRollback || s.Unknown != want.Unknown {
			t.Errorf("%q: %+v, want %+v", sql, s, want)
		}
	}
}

func TestTSQLPlaceholders(t *testing.T) {
	for sql, want := range map[string]int{
		"select * from t where a = @p1 and b = @p2": 2,
		"select @@rowcount, @p1":                    1,
		"select '@p9' -- @p8":                       0,
		"select @p3":                                3,
	} {
		if n, ok := Placeholders("sqlserver", sql); !ok || n != want {
			t.Errorf("%q: %d %v, want %d", sql, n, ok, want)
		}
	}
	if _, ok := Placeholders("sqlserver", "select @x"); ok {
		t.Error("a variable counted as a placeholder")
	}
}

func TestPlanOnly(t *testing.T) {
	p, _ := ClassifySQL("sqlserver", "delete from t")
	if q := PlanOnly(p); q.Risk != RiskRead || q.RuleIDs != nil || q.NeedsWrite() {
		t.Errorf("a planned delete: %+v", q)
	}
	p, _ = ClassifySQL("sqlserver", "exec sp_who")
	if q := PlanOnly(p); q.Risk != RiskDestructive || !q.NeedsWrite() {
		t.Errorf("a procedure is not only planned: %+v", q)
	}
}
