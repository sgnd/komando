package driver

import (
	"slices"
	"testing"
)

// "Every row" written with a WHERE that is always true is rated like no
// WHERE at all.
func TestWhereThatKeepsEveryRow(t *testing.T) {
	type c struct {
		kind, sql string
		rule      string // "" = plain write
	}
	cases := []c{
		{"bigquery", "DELETE FROM d.t WHERE true", "sql-delete-no-where"},
		{"bigquery", "DELETE d.t WHERE TRUE", "sql-delete-no-where"},
		{"bigquery", "UPDATE d.t SET a = 1 WHERE 1=1", "sql-update-no-where"},
		{"bigquery", "UPDATE d.t SET a = 1 WHERE (true)", "sql-update-no-where"},
		{"bigquery", "MERGE d.t USING d.s ON TRUE WHEN MATCHED THEN DELETE", "sql-delete-no-where"},
		{"bigquery", "MERGE d.t USING d.s ON 1=1 WHEN MATCHED THEN UPDATE SET a = 1", "sql-update-no-where"},
		{"bigquery", "MERGE d.t t USING d.s s ON t.id = s.id WHEN MATCHED THEN DELETE", ""},
		{"bigquery", "DELETE FROM d.t WHERE id = 5", ""},
		{"bigquery", "DELETE FROM d.t WHERE true AND id = 5", ""},
		{"bigquery", "DELETE FROM d.t WHERE id = 5 OR true", "sql-delete-no-where"},
		{"bigquery", "DELETE FROM d.t WHERE NOT false", "sql-delete-no-where"},
		{"clickhouse", "ALTER TABLE t DELETE WHERE 1", "sql-delete-no-where"},
		{"clickhouse", "ALTER TABLE t UPDATE a = 1 WHERE 1 = 1", "sql-update-no-where"},
		{"clickhouse", "DELETE FROM t WHERE true SETTINGS mutations_sync = 1", "sql-delete-no-where"},
		{"clickhouse", "ALTER TABLE t DELETE WHERE id = 1", ""},
		{"postgres", "DELETE FROM t WHERE true", "sql-delete-no-where"},
		{"postgres", "DELETE FROM t WHERE 'a' = 'a' RETURNING id", "sql-delete-no-where"},
		{"postgres", "UPDATE t SET a = 1 WHERE 1 = 1 AND TRUE", "sql-update-no-where"},
		{"postgres", "DELETE FROM t WHERE 1 IS NOT NULL", "sql-delete-no-where"},
		{"postgres", "DELETE FROM t WHERE id = 1", ""},
		{"postgres", "DELETE FROM t WHERE false", ""},
		{"postgres", "DELETE FROM t WHERE 0", ""},
		{"postgres", "DELETE FROM t WHERE 1 = 2", ""},
		{"postgres", "DELETE FROM t WHERE active", ""},
		{"postgres", "DELETE FROM t WHERE true = active", ""},
		{"postgres", "DELETE FROM t WHERE id IN (SELECT id FROM s WHERE true)", ""},
		{"postgres", "WITH x AS (DELETE FROM t WHERE true RETURNING *) SELECT * FROM x", "sql-delete-no-where"},
		{"mysql", "DELETE FROM t WHERE 1", "sql-delete-no-where"},
		{"mysql", "UPDATE t SET a = 1 WHERE 1 LIMIT 5", "sql-update-no-where"},
		{"mysql", "DELETE FROM t WHERE 1 = 1 ORDER BY id LIMIT 1", "sql-delete-no-where"},
		{"snowflake", "DELETE FROM t WHERE TRUE", "sql-delete-no-where"},
		{"snowflake", "MERGE INTO t USING s ON TRUE WHEN MATCHED THEN DELETE", "sql-delete-no-where"},
		{"snowflake", "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", ""},
		{"sqlite", "DELETE FROM t WHERE 1", "sql-delete-no-where"},
	}
	for _, c := range cases {
		p, err := ClassifySQL(c.kind, c.sql)
		if err != nil {
			t.Errorf("%s: %s: %v", c.kind, c.sql, err)
			continue
		}
		if c.rule == "" && (p.Risk != RiskWrite || len(p.RuleIDs) != 0) {
			t.Errorf("%s: %s: %v %v, want a plain write", c.kind, c.sql, p.Risk, p.RuleIDs)
		}
		if c.rule != "" && (p.Risk != RiskDestructive || !slices.Contains(p.RuleIDs, c.rule)) {
			t.Errorf("%s: %s: %v %v, want %s", c.kind, c.sql, p.Risk, p.RuleIDs, c.rule)
		}
	}
}
