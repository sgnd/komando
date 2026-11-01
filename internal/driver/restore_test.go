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
COPY public.t (id, name) FROM stdin;
1	a\tb
2	\N
\.
INSERT INTO t VALUES (3, 'back\slash');
/* a comment with \! inside */
\connect app
\unrestrict abc123
`,
		"mysql": `/*M!999999\- enable the sandbox mode */
-- MariaDB dump
DROP TABLE IF EXISTS ` + "`p`" + `;
INSERT INTO ` + "`p`" + ` VALUES (1,'it\'s \\ ok'),(2,'#not a comment');
DELIMITER ;;
DELIMITER ;
`,
	}
	for kind, sql := range safe {
		if err := CheckRestore(kind, strings.NewReader(sql)); err != nil {
			t.Errorf("%s: safe dump refused: %v", kind, err)
		}
	}
	unsafe := []struct{ kind, sql string }{
		{"postgres", "select 1;\n\\! rm -rf /\n"},
		{"postgres", "select 1; \\! id\n"},
		{"postgres", "\\i /etc/passwd\n"},
		{"postgres", "COPY t FROM stdin;\n1\n\\.\n\\o /tmp/x\n"},
		{"mysql", "select 1;\nsystem rm -rf /\n"},
		{"mysql", "SOURCE /etc/passwd\n"},
		{"mysql", "select 1; \\! id\n"},
	}
	for _, c := range unsafe {
		err := CheckRestore(c.kind, strings.NewReader(c.sql))
		if e, ok := err.(*out.Error); !ok || e.Code != "UNSAFE_BACKUP" {
			t.Errorf("%s %q: want UNSAFE_BACKUP, got %v", c.kind, c.sql, err)
		}
	}
}
