package driver

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// set_config only changes this session's (or transaction's) settings, so it
// is a read unless it touches komando's own safety settings or hides the
// setting's name.
func TestSetConfig(t *testing.T) {
	for sql, want := range map[string]Risk{
		"select set_config('search_path', 'app', true)":       RiskRead,
		"select set_config('work_mem', '64MB', false)":        RiskRead,
		"select set_config(name, 'x', true) from pg_settings": RiskDestructive,
	} {
		p, err := ClassifySQL("postgres", sql)
		if err != nil || p.Risk != want {
			t.Errorf("%q: want %v, got %v %v", sql, want, p.Risk, err)
		}
		if want == RiskRead && len(p.RuleIDs) > 0 {
			t.Errorf("%q flagged %v", sql, p.RuleIDs)
		}
	}
	for sql, code := range map[string]string{
		"select set_config('transaction_read_only', 'off', true)":           "SQL_TX_CONTROL",
		"select set_config('standard_conforming_strings', 'off', false)":    "SQL_STRING_RULES",
		"select SET_CONFIG( 'default_transaction_read_only' , 'off', true)": "SQL_TX_CONTROL",
	} {
		_, err := ClassifySQL("postgres", sql)
		if e, ok := err.(*out.Error); !ok || e.Code != code {
			t.Errorf("%q: want %s, got %v", sql, code, err)
		}
	}
	// pg_read_file is still flagged, with the reason that says what it does
	p, _ := ClassifySQL("postgres", "select pg_read_file('/etc/passwd')")
	if len(p.Reasons) != 1 || p.Reasons[0] != RuleReason("sql-server-file") {
		t.Errorf("pg_read_file: %+v", p.Verdict)
	}
}

func TestPlaceholders(t *testing.T) {
	cases := []struct {
		kind, sql string
		n         int
		ok        bool
	}{
		{"postgres", "select $1, $2", 2, true},
		{"postgres", "select $2::int, $1", 2, true},
		{"postgres", "select '$1', $$ $3 $$, data ? 'k' from t where id = $1", 1, true},
		{"postgres", "select 1 -- $4\n", 0, true},
		{"mysql", "select ? , '?' , `?` from t where a = ? # ?", 2, true},
		{"sqlite", "select ?, ?", 2, true},
		{"sqlite", "select ?3", 3, true},
		{"sqlite", "select :name", 0, false},
		{"sqlite", "select @name", 0, false},
	}
	for _, c := range cases {
		n, ok := Placeholders(c.kind, c.sql)
		if n != c.n || ok != c.ok {
			t.Errorf("%s %q: got %d %v, want %d %v", c.kind, c.sql, n, ok, c.n, c.ok)
		}
	}
}
