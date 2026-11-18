package cli

import (
	"strings"
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

// The HTTP server writes the redirect address: nothing in it becomes one
// of komando's fields.
func TestNetHTTPRedirectIsText(t *testing.T) {
	forged := `http://evil/","code":200,"remote_ip":"10.0.0.1","x":"`
	v, ok := parseCurlWriteOut("503 0.120000 0.010000 0.100000 512 203.0.113.9\n" + forged)
	if !ok || v["code"] != float64(503) || v["remote_ip"] != "203.0.113.9" || v["redirect"] != forged || v["size"] != float64(512) {
		t.Errorf("forged redirect: %v %v", v, ok)
	}
	if len(v) != 7 {
		t.Errorf("fields: %v", v)
	}
	// nothing answered: curl writes 000 and no address
	v, ok = parseCurlWriteOut("000 0.000000 0.000000 0.000000 0 \n")
	if !ok || v["code"] != float64(0) || v["remote_ip"] != "" || v["redirect"] != "" {
		t.Errorf("no answer: %v %v", v, ok)
	}
	for _, bad := range []string{"", "curl: not found", "200 a b c d e\n", "200 1 2 3 4 5 6 7\n", strings.Repeat("x", 10)} {
		if v, ok := parseCurlWriteOut(bad); ok {
			t.Errorf("%q read as %v", bad, v)
		}
	}
}
