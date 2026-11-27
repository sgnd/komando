package cli

import (
	"testing"
)

// MariaDB's ANALYZE <statement> explains; ANALYZE TABLE is another
// command, which the check of EXPLAIN ANALYZE never saw.
func TestMariaAnalyze(t *testing.T) {
	for in, want := range map[string]string{
		"EXPLAIN ANALYZE SELECT * FROM t":            "ANALYZE SELECT * FROM t",
		"EXPLAIN ANALYZE FORMAT=JSON SELECT 1":       "ANALYZE FORMAT=JSON SELECT 1",
		"EXPLAIN ANALYZE (SELECT 1)":                 "ANALYZE (SELECT 1)",
		"EXPLAIN ANALYZE update t set a=1 where b=2": "ANALYZE update t set a=1 where b=2",
		"SELECT 1":                                   "SELECT 1",
		"EXPLAIN ANALYZE TABLE t":                    "",
		"EXPLAIN ANALYZE table t":                    "",
		"EXPLAIN ANALYZE LOCAL TABLE t":              "",
		"EXPLAIN ANALYZE NO_WRITE_TO_BINLOG TABLE t": "",
		"EXPLAIN ANALYZE /* x */ TABLE t":            "",
		"EXPLAIN ANALYZE FORMAT=JSON TABLE t":        "",
		"EXPLAIN ANALYZE PERSISTENT FOR ALL TABLE t": "",
		"EXPLAIN ANALYZE ":                           "",
	} {
		got, err := mariaAnalyze(in)
		if (err != nil) != (want == "") || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
}
