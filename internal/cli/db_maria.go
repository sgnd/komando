package cli

import (
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// mariaPlan rewrites every statement of plan for MariaDB (mariaAnalyze).
func mariaPlan(plan *driver.SQLPlan) error {
	for i, st := range plan.Statements {
		sql, err := mariaAnalyze(st.SQL)
		if err != nil {
			return err
		}
		plan.Statements[i].SQL = sql
	}
	return nil
}

// mariaAnalyze turns the EXPLAIN ANALYZE that was checked into MariaDB's
// spelling, ANALYZE <statement>. The statement was rated as an explained
// one; ANALYZE followed by TABLE (or LOCAL, NO_WRITE_TO_BINLOG) is another
// command, which rebuilds table statistics, so only a statement MariaDB
// explains is rewritten and anything else is refused.
func mariaAnalyze(sql string) (string, error) {
	rest, ok := strings.CutPrefix(sql, "EXPLAIN ANALYZE ")
	if !ok {
		return sql, nil
	}
	words := strings.Fields(strings.ToUpper(rest))
	if len(words) > 0 && strings.HasPrefix(words[0], "FORMAT=") {
		words = words[1:]
	}
	first := ""
	if len(words) > 0 {
		first = strings.TrimLeft(words[0], "(")
		if first == "" && len(words) > 1 {
			first = words[1]
		}
	}
	if !oneOf(first, "SELECT", "WITH", "INSERT", "UPDATE", "DELETE", "REPLACE", "VALUES") {
		return "", out.Usage("MariaDB's ANALYZE explains a SELECT, INSERT, UPDATE or DELETE; give one of those to db explain --analyze")
	}
	return "ANALYZE " + rest, nil
}
