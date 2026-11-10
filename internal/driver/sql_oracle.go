package driver

import (
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/out"
)

// Oracle SQL differs from the other dialects in ways that matter here:
//
//   - Oracle runs one SQL statement per call, so a statement is rated by
//     its first word; a PL/SQL block (BEGIN ... END, DECLARE ...) holds
//     many and is code komando does not follow (opaque).
//   - DDL (CREATE, ALTER, DROP, GRANT, TRUNCATE, ...) commits before and
//     after it runs, so it always needs --write, is sent on its own, and a
//     dry run only reports it.
//   - Text quoted as q'[...]' (any delimiter) can hold quotes, and a line
//     with only / ends a PL/SQL block, as in SQL*Plus.
//
// Without --write komando runs SET TRANSACTION READ ONLY first, and checks
// after each statement that this transaction is still open (dbx).

// oracleFirst are the words an Oracle statement komando knows starts with.
var oracleFirst = map[string]bool{
	"SELECT": true, "WITH": true, "INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true,
	"CREATE": true, "ALTER": true, "DROP": true, "TRUNCATE": true, "GRANT": true, "REVOKE": true,
	"COMMENT": true, "RENAME": true, "ANALYZE": true, "AUDIT": true, "NOAUDIT": true, "PURGE": true,
	"FLASHBACK": true, "LOCK": true, "CALL": true, "SET": true, "BEGIN": true, "DECLARE": true,
	"ASSOCIATE": true, "DISASSOCIATE": true, "EXPLAIN": true, "COMMIT": true, "ROLLBACK": true, "SAVEPOINT": true,
}

// oracleDDL commit implicitly before and after they run.
var oracleDDL = map[string]bool{
	"CREATE": true, "ALTER": true, "DROP": true, "TRUNCATE": true, "GRANT": true, "REVOKE": true,
	"COMMENT": true, "RENAME": true, "ANALYZE": true, "AUDIT": true, "NOAUDIT": true, "PURGE": true,
	"FLASHBACK": true, "ASSOCIATE": true, "DISASSOCIATE": true,
}

// oracleUnits are what CREATE makes when it stores PL/SQL (or a type),
// whose text runs to the end or to a line with only /.
var oracleUnits = map[string]bool{"PROCEDURE": true, "FUNCTION": true, "PACKAGE": true, "TRIGGER": true, "TYPE": true, "LIBRARY": true, "JAVA": true}

// safePackages are the DBMS_ packages whose functions only read or compute.
var safePackages = map[string]bool{
	"DBMS_XPLAN": true, "DBMS_METADATA": true, "DBMS_RANDOM": true, "DBMS_ASSERT": true, "DBMS_CRYPTO": true,
	"DBMS_DB_VERSION": true, "DBMS_LOB": true, "DBMS_OUTPUT": true, "DBMS_ROWID": true,
}

// remotePackages reach other servers from the database server.
var remotePackages = map[string]bool{
	"UTL_HTTP": true, "UTL_TCP": true, "UTL_SMTP": true, "UTL_MAIL": true, "UTL_INADDR": true,
	"HTTPURITYPE": true, "DBMS_LDAP": true, "DBMS_CLOUD": true,
}

// unitWords reads the first words of ts: whether it is a PL/SQL block
// (anonymous: run now) or a stored unit (defined: run later).
func unitWords(ts []token) (block, defines bool) {
	var w []string
	for _, t := range ts {
		if t.word != "" && len(w) < 5 {
			w = append(w, t.word)
		}
	}
	if len(w) == 0 {
		return false, false
	}
	switch w[0] {
	case "BEGIN", "DECLARE":
		return true, false
	case "WITH": // WITH FUNCTION f ... : PL/SQL inside a query
		return len(w) > 1 && (w[1] == "FUNCTION" || w[1] == "PROCEDURE"), false
	case "CREATE":
		i := 1
		if i+1 < len(w) && w[i] == "OR" && w[i+1] == "REPLACE" {
			i += 2
		}
		if i < len(w) && (w[i] == "EDITIONABLE" || w[i] == "NONEDITIONABLE" || w[i] == "EDITIONING") {
			i++
		}
		return false, i < len(w) && oracleUnits[w[i]]
	}
	return false, false
}

// bodyRuns reports a statement whose text runs to the end, not to the next
// ; (a T-SQL procedure; Oracle PL/SQL, which a line with / ends).
func (d dialect) bodyRuns(cur []token) bool {
	if d.tsql {
		return definesBody(cur)
	}
	if d.oracle {
		block, defines := unitWords(cur)
		return block || defines
	}
	return false
}

// slashLine reports a / alone on its line at sql[i], which ends a
// statement in Oracle (as in SQL*Plus).
func slashLine(sql string, i int) bool {
	if sql[i] != '/' {
		return false
	}
	for j := i - 1; j >= 0 && sql[j] != '\n'; j-- {
		if sql[j] != ' ' && sql[j] != '\t' && sql[j] != '\r' {
			return false
		}
	}
	for j := i + 1; j < len(sql) && sql[j] != '\n'; j++ {
		if sql[j] != ' ' && sql[j] != '\t' && sql[j] != '\r' {
			return false
		}
	}
	return true
}

func hiddenCode(hint, format string, args ...any) error {
	return out.Errf(out.ExitUsage, "SQL_HIDDEN_CODE", hint, format, args...)
}

// mask returns the text splitSQL scans (Snowflake: snowflakeMask;
// BigQuery: bigqueryMask). For Oracle it is sql with each
// q'[...]' quote turned into a plain '...' of the same length (so the
// positions stay), after refusing what Oracle might read differently from
// komando: letters outside ASCII outside quotes, and -- comments with a
// character that could end the line for Oracle but not for komando.
func (d dialect) mask(sql string) (string, error) {
	if d.snowflake {
		return snowflakeMask(sql)
	}
	if d.bigquery {
		return bigqueryMask(sql)
	}
	if !d.oracle {
		return sql, nil
	}
	b := []byte(sql)
	n := len(b)
	for i := 0; i < n; {
		c := b[i]
		switch {
		case c == '-' && i+1 < n && b[i+1] == '-':
			for i += 2; i < n && b[i] != '\n'; {
				r, size := utf8.DecodeRune(b[i:])
				switch {
				case b[i] == '\r' && i+1 < n && b[i+1] == '\n':
				case b[i] < ' ' && b[i] != '\t' || b[i] == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 || r == utf8.RuneError:
					return "", hiddenCode("end -- comments with a plain line break, or use /* ... */: komando cannot tell where Oracle ends this one",
						"a -- comment holds a control character or an unusual line break")
				}
				i += size
			}
		case c == '/' && i+1 < n && b[i+1] == '*':
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return "", out.Usage("unterminated /* comment in SQL")
			}
			i += 2 + end + 2
		case c == '\'' || c == '"':
			j := i + 1
			for j < n && (b[j] != c || j+1 < n && b[j+1] == c && c == '\'') {
				if b[j] == c {
					j++
				}
				j++
			}
			if j >= n {
				return "", out.Usage("unterminated %c quote in SQL", c)
			}
			i = j + 1
		case qQuote(b, i) > 0:
			p := qQuote(b, i)
			open := b[i+p+1]
			closeCh := map[byte]byte{'[': ']', '{': '}', '<': '>', '(': ')'}[open]
			if closeCh == 0 {
				closeCh = open
			}
			end := -1
			for j := i + p + 2; j+1 < n; j++ {
				if b[j] == closeCh && b[j+1] == '\'' {
					end = j
					break
				}
			}
			if end < 0 {
				return "", out.Usage("unterminated q'%c quote in SQL", open)
			}
			for k := i; k < i+p; k++ {
				b[k] = ' '
			}
			for k := i + p + 1; k <= end; k++ {
				b[k] = 'x'
			}
			i = end + 2
		case c >= 0x80:
			return "", hiddenCode("put names with letters outside ASCII in \"double quotes\" and text in 'quotes': komando cannot tell how Oracle reads other characters",
				"Oracle SQL has a character outside ASCII that is not quoted")
		case isWord(c):
			for i < n && (isWord(b[i]) || b[i] == '$' || b[i] == '#') {
				if b[i] >= 0x80 {
					return "", hiddenCode("put names with letters outside ASCII in \"double quotes\" and text in 'quotes': komando cannot tell how Oracle reads other characters",
						"Oracle SQL has a character outside ASCII that is not quoted")
				}
				i++
			}
		default:
			i++
		}
	}
	return string(b), nil
}

// qQuote returns the length of the q or nq prefix of a q'X...X' quote at
// b[i], or 0.
func qQuote(b []byte, i int) int {
	if i > 0 && (isWord(b[i-1]) || b[i-1] == '$' || b[i-1] == '#') {
		return 0
	}
	p := 0
	if b[i] == 'n' || b[i] == 'N' {
		p = 1
	}
	if i+p+2 >= len(b) || b[i+p] != 'q' && b[i+p] != 'Q' || b[i+p+1] != '\'' {
		return 0
	}
	if o := b[i+p+2]; o == ' ' || o == '\t' || o == '\n' || o == '\r' || o >= 0x80 {
		return 0
	}
	return p + 1
}

// oracleStatement rates one Oracle statement.
func oracleStatement(ts []token) (Risk, []string, error) {
	block, defines := unitWords(ts)
	word := func(i int) string {
		if i >= 0 && i < len(ts) {
			return ts[i].word
		}
		return ""
	}
	if defines {
		// the body is stored, not run; a trigger on the whole database
		// (AFTER LOGON ON DATABASE) can lock everyone out
		for i := range ts {
			if word(i) == "ON" && word(i+1) == "DATABASE" {
				return RiskDestructive, []string{"sql-server-config"}, nil
			}
		}
		return RiskWrite, nil, nil
	}
	var risk Risk
	var rules []string
	if !block {
		var err error
		if risk, rules, err = classifyStatement(ts, true); err != nil {
			return 0, nil, err
		}
	}
	if firstWord(ts) == "MERGE" { // WHEN MATCHED THEN UPDATE (or DELETE) touches the matched rows only
		rules = slices.DeleteFunc(rules, func(id string) bool { return id == "sql-update-no-where" || id == "sql-delete-no-where" })
		if len(rules) == 0 {
			risk = RiskWrite
		}
	}
	flag := func(id string) {
		if !slices.Contains(rules, id) {
			rules = append(rules, id)
		}
		risk = RiskDestructive
	}
	if block {
		flag("sql-opaque") // PL/SQL: EXECUTE IMMEDIATE, loops, calls komando cannot follow
	}
	first := firstWord(ts)
	if !oracleFirst[first] {
		risk = max(risk, RiskWrite) // Oracle might take it for DDL, which commits
	}
	switch first {
	case "EXPLAIN":
		return 0, nil, out.Errf(out.ExitUsage, "USAGE", "use `komando db explain CONN SQL`: it shows the plan with DBMS_XPLAN",
			"EXPLAIN PLAN writes into PLAN_TABLE")
	case "AUDIT", "NOAUDIT":
		flag("sql-server-config")
	case "CREATE", "ALTER", "DROP":
		switch word(1) {
		case "PROFILE":
			flag("sql-privileges")
		case "DATABASE", "PLUGGABLE", "TABLESPACE", "DIRECTORY":
			flag("sql-server-config")
		}
	case "FLASHBACK":
		if word(1) == "DATABASE" {
			flag("sql-server-config")
		}
	}
	for i, t := range ts {
		w := t.word
		name := w
		if t.ident != "" {
			name = t.ident
		}
		switch {
		case w == "COMMIT" && word(i-1) == "ON", w == "ROLLBACK" && word(i+1) == "SEGMENT":
			// ON COMMIT PRESERVE ROWS, CREATE ROLLBACK SEGMENT
		case w == "COMMIT" || w == "ROLLBACK" || w == "SAVEPOINT" || w == "AUTONOMOUS_TRANSACTION" ||
			w == "SET" && word(i+1) == "TRANSACTION":
			return 0, nil, out.Errf(out.ExitUsage, "SQL_TX_CONTROL",
				"leave transactions to komando: without --write it runs a read-only transaction, with --write one transaction that --dry-run rolls back",
				"%s is not allowed in komando db", strings.ToLower(w))
		case (w == "EXECUTE" || w == "EXEC") && first != "GRANT" && first != "REVOKE":
			flag("sql-opaque")
		case remotePackages[name]:
			flag("sql-remote")
		case name == "UTL_FILE" || name == "BFILENAME" || name == "DBMS_DATAPUMP":
			flag("sql-server-file")
		case (strings.HasPrefix(name, "DBMS_") || strings.HasPrefix(name, "UTL_")) && !safePackages[name]:
			flag("sql-opaque") // DBMS_PIPE, DBMS_SCHEDULER, DBMS_SQL, ...: more than a read
		}
	}
	if !block {
		for _, id := range append(oracleExternal(ts), oracleCalls(ts, !oracleDDL[first])...) {
			flag(id)
		}
	}
	return risk, rules, nil
}

// oracleRows: only queries return rows (RETURNING ... INTO fills binds).
func oracleRows(kw string) bool { return kw == "SELECT" || kw == "WITH" }

// oracleNoTx: DDL commits, and ALTER SYSTEM acts at once. A word komando
// does not know may be DDL too (ADMINISTER KEY MANAGEMENT), so it is sent
// on its own, and a dry run only reports it.
func oracleNoTx(kw string, ts []token) bool {
	return !oracleFirst[kw] || oracleDDL[kw] && !(kw == "ALTER" && len(ts) > 1 && ts[1].word == "SESSION")
}

// oraclePlaceholders counts the :1, :2 (or :name) binds. Oracle binds a
// SQL statement by position, so each one takes the next --arg, also a
// name used twice; a PL/SQL block binds by name, so there a name used
// twice takes one.
func oraclePlaceholders(toks [][]token) (int, bool) {
	n := 0
	for _, ts := range toks {
		block := firstWord(ts) == "BEGIN" || firstWord(ts) == "DECLARE"
		seen := map[string]bool{}
		for i, t := range ts {
			if t.punct != ':' || i+1 >= len(ts) || ts[i+1].word == "" || ts[i+1].pos != t.pos+1 {
				continue
			}
			if w := ts[i+1].word; isDigit(w[0]) {
				if _, err := strconv.Atoi(w); err != nil {
					return 0, false
				}
			}
			if !block || !seen[ts[i+1].word] {
				n++
			}
			seen[ts[i+1].word] = true
		}
	}
	return n, true
}

// OracleBlock reports whether sql starts a PL/SQL block or stored unit,
// which a line with only / ends (db shell).
func OracleBlock(sql string) bool {
	d := dialects["oracle"]
	masked, err := d.mask(sql)
	if err != nil {
		return false
	}
	_, toks, err := splitSQL(masked, dialect{})
	if err != nil || len(toks) == 0 {
		return false
	}
	block, defines := unitWords(toks[0])
	return block || defines
}

// OracleDone reports whether sql ends with ; outside quotes and comments,
// read as Oracle reads it: \ is itself, q'[...]' may hold ', and # and $
// are part of names (db shell). SQL that komando refuses as written
// counts as done, so running it shows why.
func OracleDone(sql string) bool {
	masked, err := dialects["oracle"].mask(sql)
	if err != nil {
		e, ok := err.(*out.Error)
		return ok && e.Code == "SQL_HIDDEN_CODE"
	}
	last := byte(0)
	for i := 0; i < len(masked); i++ {
		c := masked[i]
		switch {
		case c == '\'' || c == '"':
			end := strings.IndexByte(masked[i+1:], c) // a doubled quote is two quotes in a row
			i, last = i+1+end, c
		case c == '-' && i+1 < len(masked) && masked[i+1] == '-':
			for i < len(masked) && masked[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(masked) && masked[i+1] == '*':
			i += 2 + strings.Index(masked[i+2:], "*/") + 1
		case c != ' ' && c != '\t' && c != '\n' && c != '\r':
			last = c
		}
	}
	return last == ';'
}

// oracleExplainable reports the DDL that Oracle's EXPLAIN PLAN takes
// without running it: CREATE TABLE, CREATE INDEX and ALTER INDEX.
func oracleExplainable(sql string) bool {
	_, toks, err := splitSQL(sql, dialects["oracle"])
	if err != nil || len(toks) != 1 {
		return false
	}
	var w []string
	for _, t := range toks[0] {
		if t.word != "" && len(w) < 4 {
			w = append(w, t.word)
		}
	}
	if block, defines := unitWords(toks[0]); len(w) < 2 || block || defines {
		return false
	}
	switch w[0] {
	case "ALTER":
		return w[1] == "INDEX"
	case "CREATE":
		for _, x := range w[1:] {
			switch x {
			case "TABLE", "INDEX":
				return true
			case "UNIQUE", "BITMAP", "MULTIVALUE", "GLOBAL", "PRIVATE", "TEMPORARY":
			default:
				return false
			}
		}
	}
	return false
}
