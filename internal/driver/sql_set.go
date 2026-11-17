package driver

import (
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// classifySet rates SET and RESET. done is false when the statement is
// left to classifyStatement's rules (a plain SET reads). strict (komando
// db) refuses changes to the settings komando's checks rely on.
//
// MariaDB's SET STATEMENT var=value[, ...] FOR statement runs the
// statement after FOR, which is what gets rated; without one it is no
// statement komando knows: a write, to be safe.
func classifySet(ts []token, second string, strict bool) (risk Risk, rules []string, done bool, err error) {
	if strict {
		for i, t := range ts {
			name := t.word
			afterScope := i > 0 && (ts[i-1].punct == '@' || ts[i-1].punct == '.') // @@session.x
			switch {
			case t.ident != "": // SET "standard_conforming_strings", SET `autocommit`
				name = t.ident
			case t.punct == '\'' && afterScope: // MariaDB: @@session.'autocommit'
				name = strings.ToUpper(t.str)
			}
			if afterScope && (t.ident != "" || t.punct == '\'') && strings.Contains(name, `\`) {
				// MariaDB reads @@session.'auto\commit' as autocommit
				return 0, nil, true, out.Errf(out.ExitUsage, "SQL_HIDDEN_CODE",
					"write the setting name without quotes or backslashes: komando cannot check a name it cannot read",
					"setting name %s has escapes", strings.ToLower(name))
			}
			if err := settingAllowed(name); err != nil {
				return 0, nil, true, err
			}
		}
	}
	if ts[0].word == "SET" && second == "STATEMENT" {
		if inner := setStatementInner(ts); len(inner) < len(ts) {
			risk, rules, err = classifyStatement(inner, strict)
			return risk, rules, true, err
		}
		return RiskWrite, nil, true, nil
	}
	return 0, nil, false, nil
}

// setStatementInner is the statement MariaDB's SET STATEMENT var=value
// FOR statement runs (wrapped more than once, the innermost), or ts as it
// is for anything else.
func setStatementInner(ts []token) []token {
	for len(ts) > 1 && ts[0].word == "SET" && ts[1].word == "STATEMENT" {
		at := -1
		for i := 2; i < len(ts); i++ {
			if ts[i].word == "FOR" && ts[i].depth == ts[0].depth && i+1 < len(ts) {
				at = i + 1
				break
			}
		}
		if at < 0 {
			break
		}
		ts = ts[at:]
	}
	return ts
}
