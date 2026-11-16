package driver

import (
	"slices"
	"testing"
)

// Statements that empty a table, drop its columns or delete staged files
// under another name need --allow-dangerous like TRUNCATE, DROP and REMOVE.
func TestSnowflakeOverwriteAlterPurge(t *testing.T) {
	for _, c := range []struct {
		sql  string
		want Risk
		rule string
	}{
		{"insert overwrite into t select * from s", RiskDestructive, "sql-truncate"},
		{"INSERT OVERWRITE ALL INTO t VALUES (1) SELECT 1", RiskDestructive, "sql-truncate"},
		{"insert /* c */ overwrite into t values (1)", RiskDestructive, "sql-truncate"},
		{"create or alter table t (a int)", RiskDestructive, "sql-drop"},
		{"copy into t from @s purge = true", RiskDestructive, "sql-server-file"},
		{"copy into t from @s PURGE=TRUE file_format = (type = csv)", RiskDestructive, "sql-server-file"},
		{"copy into t from @s purge = $v", RiskDestructive, "sql-server-file"},
		{"copy into t from @s purge = false", RiskWrite, ""},
		{"copy into t from @s", RiskWrite, ""},
		{"insert into t values (1)", RiskWrite, ""},
		{"insert into overwrite values (1)", RiskWrite, ""},
		{"explain insert overwrite into t select 1", RiskRead, ""},
	} {
		p, err := ClassifySQL("snowflake", c.sql)
		if err != nil {
			t.Errorf("%s: %v", c.sql, err)
			continue
		}
		if p.Risk != c.want || c.rule != "" && !slices.Contains(p.RuleIDs, c.rule) {
			t.Errorf("%s: %v %v, want %v %s", c.sql, p.Risk, p.RuleIDs, c.want, c.rule)
		}
	}
}
