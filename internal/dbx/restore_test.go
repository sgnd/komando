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
		if len(out) > 1000 { // the scanner must end, never repeat itself
			t.Fatalf("%q: no end after %q", text, out[:5])
		}
		if st.copy {
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

// TestScanPostgresLexer: the restore splits a file the way psql does
// (E-strings, nested comments, BEGIN ATOMIC bodies, $ in names) and refuses
// psql commands such as \connect instead of sending them as SQL.
func TestScanPostgresLexer(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
	}{
		{"SELECT E'it\\'s; fine';\nSELECT 2;", []string{"SELECT E'it\\'s; fine';", "SELECT 2;"}},
		{"/* a /* b */ ; c */ SELECT 1;", []string{"/* a /* b */ ; c */ SELECT 1;"}},
		{"CREATE FUNCTION f() RETURNS int LANGUAGE sql\nBEGIN ATOMIC\n  SELECT 1;\nEND;\nSELECT 2;",
			[]string{"CREATE FUNCTION f() RETURNS int LANGUAGE sql\nBEGIN ATOMIC\n  SELECT 1;\nEND;", "SELECT 2;"}},
		{"SELECT 1 AS foo$x$; SELECT $a1$;$a1$;", []string{"SELECT 1 AS foo$x$;", "SELECT $a1$;$a1$;"}},
		{"/* only a comment */\n-- and another\nSELECT 1;\n/* trailing */\n", []string{"SELECT 1;"}},
		// the last statement needs no ; and runs once
		{"SELECT 1;\nINSERT INTO t VALUES (1)\n", []string{"SELECT 1;", "INSERT INTO t VALUES (1)"}},
		{"SELECT 1;\nINSERT INTO t VALUES (1)", []string{"SELECT 1;", "INSERT INTO t VALUES (1)"}},
		{"SELECT $д$;$д$; SELECT 2;", []string{"SELECT $д$;$д$;", "SELECT 2;"}},
	}
	for _, c := range cases {
		if got := scanAll(t, "postgres", c.sql); strings.Join(got, "\n#\n") != strings.Join(c.want, "\n#\n") {
			t.Errorf("%q:\n got %q\nwant %q", c.sql, got, c.want)
		}
	}
	for _, sql := range []string{"CREATE ROLE r;\n\\connect template1\nSELECT 1;\n", "\\c app\n", "SELECT 1; \\! id\n"} {
		sc := newSQLScanner(strings.NewReader(sql), "postgres")
		var err error
		for err == nil {
			_, err = sc.next()
		}
		if err == io.EOF || !strings.Contains(err.Error(), "runs SQL only") {
			t.Errorf("%q: want a refusal, got %v", sql, err)
		}
	}
}

// TestSplitTableName: --table names are never split inside double quotes.
func TestSplitTableName(t *testing.T) {
	for in, want := range map[string]string{
		"orders":              "public|orders",
		"shop.orders":         "shop|orders",
		`public."app.events"`: "public|app.events",
		`"my.schema".orders`:  "my.schema|orders",
		`"a""b"."c.d"`:        `a"b|c.d`,
		`Shop."Order Items"`:  "Shop|Order Items",
		"a.b.c":               "error",
		"a.":                  "error",
		".a":                  "error",
		`"open`:               "error",
		`pub"lic.t`:           "error",
		"":                    "error",
	} {
		s, n, err := splitTableName(in)
		got := s + "|" + n
		if err != nil {
			got = "error"
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestScanMySQLDashes(t *testing.T) {
	got := scanAll(t, "mysql", "SELECT 1--1;\nSELECT 2; -- note\n/*M!999999\\- enable the sandbox mode */\nSELECT 3;\n")
	want := []string{"SELECT 1--1", "SELECT 2", "/*M!999999\\- enable the sandbox mode */\nSELECT 3"}
	if strings.Join(got, "\n#\n") != strings.Join(want, "\n#\n") {
		t.Errorf("got %q\nwant %q", got, want)
	}
	cases := []struct {
		sql  string
		want []string
	}{
		// the last statement needs no delimiter and runs once
		{"SELECT 1;\nINSERT INTO t VALUES (1)\n", []string{"SELECT 1", "INSERT INTO t VALUES (1)"}},
		// a comment-only chunk is left out of the next statement
		{"/* c */; SELECT 1;", []string{"SELECT 1"}},
		{"SELECT 0; /* c */; SELECT 1;\n", []string{"SELECT 0", "SELECT 1"}},
		{"DELIMITER\t;;\nCREATE PROCEDURE p() BEGIN SELECT 1; END;;\nDELIMITER ;\nSELECT 2;", []string{"CREATE PROCEDURE p() BEGIN SELECT 1; END", "SELECT 2"}},
		{"SELECT `a\\`;\nSELECT 2;", []string{"SELECT `a\\`", "SELECT 2"}},
	}
	for _, c := range cases {
		if got := scanAll(t, "mysql", c.sql); strings.Join(got, "\n#\n") != strings.Join(c.want, "\n#\n") {
			t.Errorf("%q:\n got %q\nwant %q", c.sql, got, c.want)
		}
	}
	sc := newSQLScanner(strings.NewReader("DELIMITER ;; -- x\nSELECT 1;;\n"), "mysql")
	if _, err := sc.next(); err == nil || err == io.EOF {
		t.Errorf("DELIMITER with more text: want a refusal, got %v", err)
	}
}
