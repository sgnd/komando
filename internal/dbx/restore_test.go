package dbx

import (
	"io"
	"strings"
	"testing"
)

func scanAll(t *testing.T, kind, text string) []string {
	t.Helper()
	sc := newSQLScanner(strings.NewReader(text), kind)
	var out []string
	for {
		st, err := sc.next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if pgCopyFrom.MatchString(st.text) {
			var data []string
			for {
				l, err := sc.rawLine()
				if err != nil || l == `\.` {
					break
				}
				data = append(data, l)
			}
			out = append(out, st.text+" <"+strings.Join(data, "|")+">")
			continue
		}
		out = append(out, st.text)
	}
}

func TestScanPostgres(t *testing.T) {
	got := scanAll(t, "postgres", `-- komando dump
\restrict abc123
SET client_encoding = 'UTF8';
CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $body$
begin
  return 1; -- inside the body
end;
$body$;
COPY public.t (a, b) FROM stdin;
1	x;y
2	\N
\.
SELECT 'a;b', "c;d"; SELECT 2;
/* a ; comment */ SELECT 3;
\unrestrict abc123
`)
	want := []string{
		"SET client_encoding = 'UTF8';",
		"CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $body$\nbegin\n  return 1; -- inside the body\nend;\n$body$;",
		"COPY public.t (a, b) FROM stdin; <1\tx;y|2\t\\N>",
		`SELECT 'a;b', "c;d";`,
		"SELECT 2;",
		"/* a ; comment */ SELECT 3;",
	}
	if strings.Join(got, "\n#\n") != strings.Join(want, "\n#\n") {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
}

func TestScanMySQL(t *testing.T) {
	got := scanAll(t, "mysql", "/*!40101 SET NAMES utf8mb4 */;\n"+
		"INSERT INTO `t` VALUES ('it\\'s; fine',0x00),('two');\n"+
		"# a comment ;\n"+
		"DELIMITER ;;\n"+
		"CREATE PROCEDURE p() BEGIN SELECT 1; SELECT 2; END;;\n"+
		"DELIMITER ;\n"+
		"SELECT 3;\n")
	want := []string{
		"/*!40101 SET NAMES utf8mb4 */",
		"INSERT INTO `t` VALUES ('it\\'s; fine',0x00),('two')",
		"CREATE PROCEDURE p() BEGIN SELECT 1; SELECT 2; END",
		"SELECT 3",
	}
	if strings.Join(got, "\n#\n") != strings.Join(want, "\n#\n") {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
}

func TestMySQLQuoteAndDefiner(t *testing.T) {
	if got := mysqlQuote("a'b\\c\n\x00"); got != `'a\'b\\c\n\0'` {
		t.Errorf("quote: %s", got)
	}
	in := "CREATE DEFINER=`root`@`%` TRIGGER `t` BEFORE INSERT ON `x` FOR EACH ROW SET NEW.a = 1"
	if got := stripDefiner(in); got != "CREATE TRIGGER `t` BEFORE INSERT ON `x` FOR EACH ROW SET NEW.a = 1" {
		t.Errorf("definer: %s", got)
	}
	if got := stripDefiner("CREATE VIEW v AS SELECT 1"); got != "CREATE VIEW v AS SELECT 1" {
		t.Errorf("no definer: %s", got)
	}
}
