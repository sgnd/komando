package driver

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestCheckRestore(t *testing.T) {
	safe := map[string]string{
		"postgres": `--
-- PostgreSQL database dump
--
\restrict abc123
SET standard_conforming_strings = on;
CREATE FUNCTION f() RETURNS text AS $$ select '\d+' $$ LANGUAGE sql;
CREATE FUNCTION g() RETURNS text AS $a1$ select 'x' $a1$ LANGUAGE sql;
COPY public.t (id, name) FROM stdin;
1	a\tb
2	\N
\.
INSERT INTO t VALUES (3, 'back\slash'), (4, E'it\'s \\ fine');
SELECT 1 AS foo$x$, $1;
/* a comment with \! inside /* nested */ still \! comment */
CREATE FUNCTION h() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; SELECT 2; END;
\unrestrict abc123
`,
		"mysql": `/*M!999999\- enable the sandbox mode */
-- MariaDB dump
/*!40101 SET NAMES utf8mb4 */;
DROP TABLE IF EXISTS ` + "`p`" + `;
INSERT INTO ` + "`p`" + ` VALUES (1,'it\'s \\ ok'),(2,'#not a comment'),(3,\N);
DELIMITER ;;
CREATE PROCEDURE q() BEGIN SELECT 1; END;;
DELIMITER ;
SELECT 1--1;
`,
	}
	for kind, sql := range safe {
		if _, err := CheckRestore(kind, strings.NewReader(sql)); err != nil {
			t.Errorf("%s: safe dump refused: %v", kind, err)
		}
	}
	// files that real dumps or hand-written SQL contain, which must pass
	more := []struct{ name, kind, sql string }{
		{"mysql setting name in data", "mysql", "INSERT INTO `notes` VALUES (1,'set NO_BACKSLASH_ESCAPES to fix it');\n"},
		{"mysql setting name in a comment", "mysql", "-- NO_BACKSLASH_ESCAPES is off\n/* SET sql_mode='NO_BACKSLASH_ESCAPES' */\nSELECT 1;\n"},
		{"pg setting name in a comment", "postgres", "-- see standard_conforming_strings\nSELECT 1;\n"},
		{"pg setting name in data", "postgres", "INSERT INTO t VALUES ('standard_conforming_strings off');\n"},
		{"pg conforming on", "postgres", "SET standard_conforming_strings TO 'on';\nSET LOCAL standard_conforming_strings = true;\n"},
		{"pg set_config literal", "postgres", "SELECT pg_catalog.set_config('search_path', '', false);\n"},
		{"mysqldump sql_mode save and restore", "mysql", `/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES' */ ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
`},
		{"mysql column named source in a routine", "mysql", "DELIMITER ;;\nCREATE PROCEDURE p()\nBEGIN\n  SELECT id,\n  source\n  FROM t;\nEND ;;\nDELIMITER ;\n"},
		{"mysql backslash at the end of a name", "mysql", "CREATE TABLE `a\\` (x int);\nSELECT '\\'';\n"},
		{"pg non-Latin dollar tag", "postgres", "CREATE FUNCTION f() RETURNS text AS $д$ select 'a;\\' $д$ LANGUAGE sql;\nSELECT $标签$;'$标签$;\n"},
		{"last statement without ;", "mysql", "SELECT 1;\nINSERT INTO t VALUES (1)\n"},
	}
	for _, c := range more {
		if v, err := CheckRestore(c.kind, strings.NewReader(c.sql)); err != nil || len(v.RuleIDs) > 0 {
			t.Errorf("%s: %q refused: %v %v", c.name, c.sql, err, v.RuleIDs)
		}
	}
	refused := []struct{ name, kind, sql, code string }{
		{"pg shell", "postgres", "select 1;\n\\! rm -rf /\n", "UNSAFE_BACKUP"},
		{"pg shell mid-line", "postgres", "select 1; \\! id\n", "UNSAFE_BACKUP"},
		{"pg include", "postgres", "\\i /etc/passwd\n", "UNSAFE_BACKUP"},
		{"pg after copy", "postgres", "COPY t FROM stdin;\n1\n\\.\n\\o /tmp/x\n", "UNSAFE_BACKUP"},
		{"mysql system", "mysql", "select 1;\nsystem rm -rf /\n", "UNSAFE_BACKUP"},
		{"mysql source", "mysql", "SOURCE /etc/passwd\n", "UNSAFE_BACKUP"},
		{"mysql shell mid-line", "mysql", "select 1; \\! id\n", "UNSAFE_BACKUP"},
		// psql and the mysql client read these differently from a naive lexer
		{"pg E-string", "postgres", "SELECT E'\\'';\n\\! touch /tmp/pwned\n", "UNSAFE_BACKUP"},
		{"pg $ in a name", "postgres", "SELECT 1 AS foo$x$;\n\\! touch /tmp/pwned\n", "UNSAFE_BACKUP"},
		{"pg digit dollar tag", "postgres", "SELECT $a1$'$a1$;\n\\! touch /tmp/pwned\n", "UNSAFE_BACKUP"},
		{"pg nested comment", "postgres", "/* /* */ ' */ \\! touch /tmp/pwned\n", "UNSAFE_BACKUP"},
		{"pg connect tail", "postgres", "\\connect postgres \\! touch /tmp/pwned\n", "RESTORE_UNSUPPORTED"},
		{"pg connect", "postgres", "CREATE DATABASE app;\n\\connect app\nSELECT 1;\n", "RESTORE_UNSUPPORTED"},
		{"pg c", "postgres", "\\c template1\n", "RESTORE_UNSUPPORTED"},
		{"pg restrict with more", "postgres", "\\restrict abc \\! id\n", "UNSAFE_BACKUP"},
		{"pg fake copy", "postgres", "WITH stdin AS (SELECT 1) SELECT 1 AS\nCOPY FROM stdin;\n\\! touch /tmp/pwned\n\\.\n", "UNSAFE_BACKUP"},
		{"pg copy then text", "postgres", "COPY t FROM stdin; SELECT 1;\n1\n\\.\n", "UNSAFE_BACKUP"},
		{"pg copy without end", "postgres", "COPY t FROM stdin;\n1\n", "UNSAFE_BACKUP"},
		{"pg open quote at end", "postgres", "SELECT 'abc\n\\! id\n", "UNSAFE_BACKUP"},
		{"pg open dollar at end", "postgres", "SELECT $$ abc\n", "UNSAFE_BACKUP"},
		{"pg open comment at end", "postgres", "/* abc\n", "UNSAFE_BACKUP"},
		{"pg conforming strings off", "postgres", "SET standard_conforming_strings = off;\nSELECT '\\';\n\\! id\n", "UNSAFE_BACKUP"},
		{"pg set_config conforming", "postgres", "SELECT set_config('standard_conforming_strings', 'off', false);\n", "UNSAFE_BACKUP"},
		{"mysql dash no space", "mysql", "SELECT 1 --\\! touch /tmp/pwned\n;\n", "UNSAFE_BACKUP"},
		{"mysql dash quote", "mysql", "SELECT 1--';\n\\! touch /tmp/pwned\nSELECT '';\n", "UNSAFE_BACKUP"},
		{"mysql exec comment", "mysql", "/*!40101 \\! touch /tmp/pwned */;\n", "UNSAFE_BACKUP"},
		{"mysql no backslash escapes", "mysql", "SET sql_mode='NO_BACKSLASH_ESCAPES';\nSELECT '\\';\n\\! touch /tmp/pwned\nSELECT '';\n", "UNSAFE_BACKUP"},
		{"mysql backslash in delimiter", "mysql", "DELIMITER \\!\n", "UNSAFE_BACKUP"},
		{"mysql delimiter with more", "mysql", "DELIMITER ;; -- x\nSELECT 1;;\n", "UNSAFE_BACKUP"},
		{"mysql quoted delimiter", "mysql", "DELIMITER ';'\n", "UNSAFE_BACKUP"},
		{"mysql sql_mode computed", "mysql", "SET sql_mode=CONCAT('NO_BACKSLASH','_ESCAPES');\n", "UNSAFE_BACKUP"},
		{"mysql sql_mode concatenated literals", "mysql", "SET SESSION sql_mode='NO_BACKSLASH' '_ESCAPES';\n", "UNSAFE_BACKUP"},
		{"mysql sql_mode in exec comment", "mysql", "/*!40101 SET @@session.sql_mode='NO_BACKSLASH_ESCAPES' */;\n", "UNSAFE_BACKUP"},
		{"mysql sql_mode from a changed variable", "mysql", "SET @m=@@sql_mode;\nSET @m='NO_BACKSLASH_ESCAPES';\nSET sql_mode=@m;\n", "UNSAFE_BACKUP"},
		{"mysql sql_mode from an unknown variable", "mysql", "SET sql_mode=@m;\n", "UNSAFE_BACKUP"},
		{"mysql sql_mode after the sandbox line", "mysql", "/*M!999999\\- enable the sandbox mode */ SET sql_mode='NO_BACKSLASH_ESCAPES';\n", "UNSAFE_BACKUP"},
		{"pg set_config computed name", "postgres", "SELECT set_config('standard_'||'conforming_strings','off',false);\n", "UNSAFE_BACKUP"},
		{"pg quoted set_config", "postgres", "SELECT \"set_config\"('standard_conforming_strings','off',false);\n", "UNSAFE_BACKUP"},
		{"pg reset all", "postgres", "RESET ALL;\n", "UNSAFE_BACKUP"},
		{"pg conforming on and more", "postgres", "SET standard_conforming_strings = on, off;\n", "UNSAFE_BACKUP"},
		{"mysql open quote at end", "mysql", "SELECT 'abc;\n", "UNSAFE_BACKUP"},
	}
	for _, c := range refused {
		_, err := CheckRestore(c.kind, strings.NewReader(c.sql))
		if e, ok := err.(*out.Error); !ok || e.Code != c.code {
			t.Errorf("%s: %q: want %s, got %v", c.name, c.sql, c.code, err)
		}
	}
}

// TestCheckRestoreRules: what a file does beyond writing data is named,
// with its first line, so the human who allows the restore sees it.
func TestCheckRestoreRules(t *testing.T) {
	cases := []struct {
		name, kind, sql string
		want            []string
		reason          string
	}{
		{"pg dump", "postgres", "SET standard_conforming_strings = on;\nCREATE TABLE t (id int);\nCOPY t (id) FROM stdin;\n1\n\\.\nDROP TABLE x;\n", nil, ""},
		{"copy program", "postgres", "SELECT 1;\n\nCOPY t FROM PROGRAM 'id';\nCOPY u FROM PROGRAM 'id';\n", []string{"sql-program"}, "(line 3 and 1 more)"},
		{"server files", "postgres", "SELECT pg_read_file('/etc/passwd');\n", []string{"sql-server-file"}, "(line 1)"},
		{"alter system and superuser", "postgres", "ALTER SYSTEM SET wal_level = logical;\nCREATE ROLE r SUPERUSER;\n", []string{"sql-server-config", "sql-privileges"}, ""},
		{"no ; at the end", "postgres", "SELECT 1;\nCOPY t TO PROGRAM 'id'\n", []string{"sql-program"}, "(line 2)"},
		{"mysql outfile", "mysql", "/*!40101 SET NAMES utf8mb4 */;\nSELECT * FROM t INTO OUTFILE '/tmp/x';\n", []string{"sql-server-file"}, "(line 2)"},
		{"mysql outfile in exec comment", "mysql", "/*!50000 SELECT 1 INTO DUMPFILE '/tmp/x' */;\n", []string{"sql-server-file"}, ""},
		{"mysql routine body", "mysql", "DELIMITER ;;\nCREATE PROCEDURE p()\nBEGIN\n  SELECT 1 INTO OUTFILE '/tmp/x';\nEND;;\nDELIMITER ;\n", []string{"sql-server-file"}, "(line 2)"},
		{"mysql prepare", "mysql", "PREPARE s FROM @q;\nEXECUTE s;\n", []string{"sql-opaque"}, ""},
		{"mysql gtid", "mysql", "SET @@GLOBAL.GTID_PURGED='x';\n", []string{"sql-server-config"}, ""},
	}
	for _, c := range cases {
		v, err := CheckRestore(c.kind, strings.NewReader(c.sql))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if strings.Join(v.RuleIDs, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: rules %v, want %v", c.name, v.RuleIDs, c.want)
		}
		if c.reason != "" && (len(v.Reasons) == 0 || !strings.Contains(v.Reasons[0], c.reason)) {
			t.Errorf("%s: reasons %q, want %q", c.name, v.Reasons, c.reason)
		}
		if (len(c.want) > 0) != (v.Risk == RiskDestructive) {
			t.Errorf("%s: risk %v", c.name, v.Risk)
		}
	}
}

func TestParseDelimiter(t *testing.T) {
	cases := []struct {
		line, want string
		ok         bool
	}{
		{"DELIMITER ;;", ";;", true},
		{"delimiter\t$$", "$$", true},
		{"DELIMITER ;; -- x", "", true},
		{"DELIMITER", "", false},
		{"DELIMITER ';'", "", true},
		{"DELIMITERS ;", "", false},
		{"SELECT 1", "", false},
	}
	for _, c := range cases {
		if got, ok := ParseDelimiter(c.line); got != c.want || ok != c.ok {
			t.Errorf("%q: got %q %v, want %q %v", c.line, got, ok, c.want, c.ok)
		}
	}
}

// TestLexerStatements checks where statements end, as psql and the mysql
// client split them.
func TestLexerStatements(t *testing.T) {
	cases := []struct {
		kind, sql string
		want      []string
	}{
		{"postgres", "SELECT E'it\\'s; fine'; SELECT 2;", []string{"SELECT ''", "SELECT 2"}},
		{"postgres", "/* a /* b */ ; c */ SELECT 1;", []string{"SELECT 1"}},
		{"postgres", "CREATE FUNCTION f() RETURNS int LANGUAGE sql\nBEGIN ATOMIC\n SELECT 1;\n SELECT CASE WHEN true THEN 1 END;\nEND;\nSELECT 3;",
			[]string{"CREATE FUNCTION F() RETURNS INT LANGUAGE SQL BEGIN ATOMIC SELECT 1; SELECT CASE WHEN TRUE THEN 1 END; END", "SELECT 3"}},
		{"postgres", "BEGIN; SELECT 1; END;", []string{"BEGIN", "SELECT 1", "END"}},
		{"postgres", "CREATE RULE r AS ON INSERT TO t DO ALSO (SELECT 1; SELECT 2); SELECT 3;", []string{"CREATE RULE R AS ON INSERT TO T DO ALSO (SELECT 1; SELECT 2)", "SELECT 3"}},
		{"postgres", "SELECT $f$;$f$, foo$x$; SELECT 2;", []string{"SELECT '', FOO$X$", "SELECT 2"}},
		{"mysql", "SELECT 1--1; SELECT 2; -- c;\nSELECT 'a;\\'b', `c;d`;", []string{"SELECT 1--1", "SELECT 2", "SELECT '', ``"}},
		{"mysql", "/*!40101 SET NAMES utf8 */; # x;\nSELECT 1;", []string{"/*!40101 SET NAMES UTF8 */", "SELECT 1"}},
		{"mysql", "SELECT `a\\`; SELECT 'b\\';';", []string{"SELECT ``", "SELECT ''"}},
		{"postgres", "SELECT $д$;$д$; SELECT $标签$;'$标签$; SELECT 3;", []string{"SELECT ''", "SELECT ''", "SELECT 3"}},
	}
	for _, c := range cases {
		l := NewLexer(c.kind)
		var got []string
		for _, line := range strings.Split(c.sql, "\n") {
			for pos := 0; pos < len(line); {
				end, cmd := l.Next(line, pos)
				if cmd >= 0 {
					t.Fatalf("%q: client command at %d", c.sql, cmd)
				}
				if end < 0 {
					break
				}
				got = append(got, l.Last())
				pos = end
			}
			l.EndLine()
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s %q:\n got %q\nwant %q", c.kind, c.sql, got, c.want)
		}
	}
}
