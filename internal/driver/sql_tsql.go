package driver

import (
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/out"
)

// T-SQL (SQL Server) needs more care than the other dialects:
//
//   - a statement needs no ; before the next one ("SELECT 1 DELETE FROM t"
//     is two statements), so a keyword anywhere counts, not only the first;
//   - a bare name as the first word runs a stored procedure (sp_who);
//   - there is no read-only transaction. Without --write komando runs the
//     SQL in a transaction it always rolls back, and checks after each
//     statement that the transaction is still open (dbx).
//
// Its keywords (INSERT, DROP, EXEC, COMMIT, ...) are reserved words: a
// name spelled like one must be quoted ([drop], "drop"), so a keyword
// outside quotes is the keyword.

// tsqlFirst are the words a T-SQL statement komando knows starts with.
// Any other first word is the name of a procedure SQL Server runs.
var tsqlFirst = map[string]bool{
	"SELECT": true, "WITH": true, "SET": true, "USE": true, "DECLARE": true, "PRINT": true,
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true, "CREATE": true, "ALTER": true, "DROP": true,
	"TRUNCATE": true, "GRANT": true, "REVOKE": true, "DENY": true, "EXEC": true, "EXECUTE": true,
	"KILL": true, "SHUTDOWN": true, "BACKUP": true, "RESTORE": true, "DBCC": true, "RECONFIGURE": true,
	"BULK": true, "CHECKPOINT": true, "WAITFOR": true, "IF": true, "WHILE": true, "RETURN": true,
	"GOTO": true, "BREAK": true, "CONTINUE": true, "THROW": true, "RAISERROR": true, "OPEN": true,
	"FETCH": true, "CLOSE": true, "DEALLOCATE": true, "REVERT": true, "SETUSER": true, "READTEXT": true,
	"WRITETEXT": true, "UPDATETEXT": true, "ENABLE": true, "DISABLE": true,
	"BEGIN": true, "COMMIT": true, "ROLLBACK": true, "SAVE": true, "END": true,
}

// tsqlTx end or start a transaction wherever they stand.
var tsqlTx = map[string]bool{"BEGIN": true, "COMMIT": true, "ROLLBACK": true, "SAVE": true, "TRAN": true, "TRANSACTION": true}

// planSettings would turn db explain's SET SHOWPLAN_TEXT off, or change
// whether statements run at all.
var planSettings = map[string]bool{
	"SHOWPLAN_TEXT": true, "SHOWPLAN_ALL": true, "SHOWPLAN_XML": true, "NOEXEC": true, "PARSEONLY": true, "FMTONLY": true,
}

// tsqlWrites change something wherever they stand.
var tsqlWrites = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true, "CREATE": true, "ALTER": true,
	"WRITETEXT": true, "UPDATETEXT": true, "CHECKPOINT": true, "WAITFOR": true, "REVERT": true,
}

// principals follow CREATE, ALTER or DROP when users or rights change.
var principals = map[string]bool{
	"LOGIN": true, "USER": true, "ROLE": true, "APPLICATION": true, "AUTHORIZATION": true, "CREDENTIAL": true,
}

// serverScopes follow ALTER when the change is server-wide.
var serverScopes = map[string]bool{"DATABASE": true, "SERVER": true, "ENDPOINT": true, "RESOURCE": true, "AVAILABILITY": true}

// tsqlFileWords read or write files on the server (BULK INSERT,
// OPENROWSET(BULK ...), backups).
var tsqlFileWords = map[string]bool{"BACKUP": true, "RESTORE": true, "BULK": true, "OPENROWSET": true, "OPENDATASOURCE": true}

// nests reports whether /* comments nest (Postgres, SQL Server, ClickHouse).
func (d dialect) nests() bool { return d.dollar || d.tsql || d.clickhouse }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// tsqlNumberEnd returns where the number literal at sql[i] ends, read
// the way SQL Server reads it: 0x and hex digits (0x alone is an empty
// binary), or digits, an optional .digits and an optional e, sign and
// digits (1e and 1.e are floats). The next token starts right after, so
// 0xROLLBACK is 0x ROLLBACK and 1eDROP is 1e DROP.
func tsqlNumberEnd(sql string, i int) int {
	n := len(sql)
	digits := func(j int, ok func(byte) bool) int {
		for j < n && ok(sql[j]) {
			j++
		}
		return j
	}
	if i+1 < n && sql[i] == '0' && (sql[i+1] == 'x' || sql[i+1] == 'X') {
		return digits(i+2, func(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' })
	}
	j := digits(i, isDigit)
	if j < n && sql[j] == '.' {
		j = digits(j+1, isDigit)
	}
	if j < n && (sql[j] == 'e' || sql[j] == 'E') {
		j++
		if j+1 < n && (sql[j] == '+' || sql[j] == '-') && isDigit(sql[j+1]) {
			j++
		}
		j = digits(j, isDigit)
	}
	return j
}

// commentEnd reports whether sql[i] ends a -- comment. SQL Server is
// given more ends than \n: if it ended the comment where komando does
// not, the rest would run unseen. Ending too early only shows komando
// more text, which is refused below if it is not plain ASCII.
func (d dialect) commentEnd(sql string, i int) bool {
	c := sql[i]
	switch {
	case c == '\n' || d.crComments && c == '\r':
		return true
	case !d.tsql:
		return false
	case c < ' ' && c != '\t' || c == 0x7f:
		return true
	case c >= 0x80 && c < 0xc0: // inside a character whose first byte was checked
		return false
	case c >= 0x80:
		r, _ := utf8.DecodeRuneInString(sql[i:])
		return r == 0x85 || r == 0x2028 || r == 0x2029 || r == utf8.RuneError
	}
	return false
}

// skipComment returns the position after the /* comment at sql[i].
func (d dialect) skipComment(sql string, i int) (int, error) {
	n, level := len(sql), 0
	for i < n {
		if i+1 < n && sql[i] == '/' && sql[i+1] == '*' {
			level++
			i += 2
		} else if i+1 < n && sql[i] == '*' && sql[i+1] == '/' {
			level--
			i += 2
			if level == 0 || !d.nests() {
				break
			}
		} else {
			i++
		}
	}
	if level > 0 && d.nests() {
		return i, out.Usage("unterminated /* comment in SQL")
	}
	return i, nil
}

// classifyFor is classifyStatement with the T-SQL, Oracle or ClickHouse rules on top.
func classifyFor(kind string, ts []token) (Risk, []string, error) {
	switch kind {
	case "oracle":
		return oracleStatement(ts)
	case "clickhouse":
		return clickhouseStatement(ts)
	case "snowflake":
		return snowflakeStatement(ts)
	}
	risk, rules, err := classifyStatement(ts, true)
	if err != nil || kind != "sqlserver" {
		return risk, rules, err
	}
	return tsqlStatement(ts, risk, rules)
}

// unknownNeedsWrite are the kinds where a statement komando does not know
// needs --write: their read-only transaction does not cover everything
// (MySQL admin statements, Oracle DDL), or there is none (SQL Server,
// ClickHouse, Snowflake).
var unknownNeedsWrite = map[string]bool{"mysql": true, "sqlserver": true, "oracle": true, "clickhouse": true, "snowflake": true}

// unknownFirst reports a first word komando does not know.
func unknownFirst(kind, kw string) bool {
	switch kind {
	case "sqlserver":
		return !tsqlFirst[kw]
	case "oracle":
		return !oracleFirst[kw]
	case "clickhouse":
		return !chFirst[kw]
	case "snowflake":
		return !sfFirst[kw]
	}
	return !readFirst[kw] && !writeFirst[kw] && !opaqueFirst[kw]
}

// definesBody reports CREATE or ALTER of a procedure, function or
// trigger: SQL Server takes the rest of the batch as its body, which is
// stored, not run.
func definesBody(ts []token) bool {
	var w []string
	for _, t := range ts {
		if t.word != "" && len(w) < 4 {
			w = append(w, t.word)
		}
	}
	if len(w) < 2 || w[0] != "CREATE" && w[0] != "ALTER" {
		return false
	}
	obj := w[1]
	if obj == "OR" && len(w) > 3 && w[2] == "ALTER" {
		obj = w[3]
	}
	return obj == "PROC" || obj == "PROCEDURE" || obj == "FUNCTION" || obj == "TRIGGER"
}

// tsqlStatement adds the T-SQL rules to the verdict classifyStatement gave.
func tsqlStatement(ts []token, risk Risk, rules []string) (Risk, []string, error) {
	for _, t := range ts {
		if strings.IndexFunc(t.word, func(r rune) bool { return r >= utf8.RuneSelf }) >= 0 {
			return 0, nil, out.Errf(out.ExitUsage, "SQL_HIDDEN_CODE",
				"put names with letters outside ASCII in [brackets] and text in quotes (N'...'): komando cannot tell how SQL Server reads other characters",
				"SQL Server SQL has a character outside ASCII that is not quoted (%s)", strings.ToLower(t.word))
		}
	}
	word := func(i int) string {
		if i >= 0 && i < len(ts) {
			return ts[i].word
		}
		return ""
	}
	flag := func(id string) {
		if !slices.Contains(rules, id) {
			rules = append(rules, id)
		}
		risk = RiskDestructive
	}
	first := firstWord(ts)
	serverTrigger := false
	for i := range ts {
		if word(i) == "ON" && word(i+1) == "ALL" && word(i+2) == "SERVER" {
			serverTrigger = true // a server-wide trigger (a logon trigger can lock everyone out)
		}
	}
	if definesBody(ts) {
		// the body is stored, not run: what it would do counts when it runs
		if serverTrigger {
			return RiskDestructive, []string{"sql-server-config"}, nil
		}
		return RiskWrite, nil, nil
	}
	if !tsqlFirst[first] {
		flag("sql-opaque") // a bare name runs that procedure
	}
	if serverTrigger {
		flag("sql-server-config")
	}
	privilegeList := first == "GRANT" || first == "REVOKE" || first == "DENY"
	writes := false
	for i, t := range ts {
		w, next := t.word, word(i+1)
		switch {
		case w == "":
		case tsqlTx[w] && !(w == "ROLLBACK" && word(i-1) == "WITH"): // ALTER DATABASE ... WITH ROLLBACK IMMEDIATE
			return 0, nil, out.Errf(out.ExitUsage, "SQL_TX_CONTROL",
				"leave transactions to komando, and send each statement on its own (BEGIN ... END blocks and TRY ... CATCH belong in a stored procedure)",
				"%s is not allowed in komando db", w)
		case txSettings[w] || planSettings[w]:
			return 0, nil, out.Errf(out.ExitUsage, "SQL_TX_CONTROL",
				"leave this setting to komando: it runs SQL in its own transaction, and `komando db explain` shows plans",
				"changing %s is not allowed in komando db", strings.ToLower(w))
		case (w == "EXEC" || w == "EXECUTE") && !privilegeList, w == "CALL" && i > 0 && ts[i-1].punct == '{':
			flag("sql-opaque")
		case w == "KILL" || w == "SHUTDOWN":
			flag("sql-kill")
		case (w == "CREATE" || w == "ALTER" || w == "DROP") && (principals[next] || next == "SERVER" && word(i+2) == "ROLE"),
			w == "GRANT" || w == "REVOKE" || w == "DENY" || w == "SETUSER":
			flag("sql-privileges")
		case w == "DROP":
			flag("sql-drop")
		case w == "TRUNCATE":
			flag("sql-truncate")
		case tsqlFileWords[w]:
			flag("sql-server-file")
		case w == "OPENQUERY":
			flag("sql-remote")
		case w == "RECONFIGURE" || w == "DBCC" || w == "ALTER" && serverScopes[next]:
			flag("sql-server-config")
		case tsqlWrites[w], w == "NEXT" && next == "VALUE", serviceBroker(ts, i):
			writes = true
		}
	}
	if writes {
		risk = max(risk, RiskWrite)
	}
	if first == "UPDATE" && word(1) == "STATISTICS" { // a refresh of the planner's numbers, not of rows
		rules = slices.DeleteFunc(rules, func(id string) bool { return id == "sql-update-no-where" })
		if len(rules) == 0 {
			risk = RiskWrite
		}
	}
	if (first == "DECLARE" || first == "PRINT") && !writes && len(rules) == 0 {
		risk = RiskRead
	}
	return risk, rules, nil
}

// serviceBroker reports a Service Broker statement at ts[i] that changes
// a queue (RECEIVE, SEND, END, MOVE or GET CONVERSATION). SQL Server wants
// a ; before one that is not first, but komando does not count on that.
// The words alone are no sign: they are not reserved, so tables may have
// columns with these names.
func serviceBroker(ts []token, i int) bool {
	word := func(k int) string {
		if k >= 0 && k < len(ts) {
			return ts[k].word
		}
		return ""
	}
	switch ts[i].word {
	case "RECEIVE":
		return word(i+1) == "TOP" || i+1 < len(ts) && ts[i+1].punct == '*'
	case "CONVERSATION":
		prev := word(i - 1)
		return prev == "END" || prev == "MOVE" || prev == "GET" || prev == "ON" && word(i-2) == "SEND"
	}
	return false
}

// tsqlRows reports T-SQL statements that may return rows besides the
// reads: a procedure, and changes with an OUTPUT clause.
func tsqlRows(kw string, ts []token) bool {
	switch {
	case kw == "EXEC" || kw == "EXECUTE" || !tsqlFirst[kw]:
		return true
	case kw == "INSERT" || kw == "UPDATE" || kw == "DELETE" || kw == "MERGE":
		return hasWord(ts, "OUTPUT")
	}
	return false
}

// rowsFor reports a statement that returns rows.
func rowsFor(kind, kw string, ts []token) bool {
	switch kind {
	case "oracle":
		return oracleRows(kw)
	case "clickhouse":
		return clickhouseRows(kw)
	case "snowflake":
		return snowflakeRows(kw)
	case "sqlserver":
		return returnsRows(kw, ts) || tsqlRows(kw, ts)
	}
	return returnsRows(kw, ts)
}

// otherNoTx is noTx for SQL Server, Oracle, ClickHouse and Snowflake (no
// transactions komando can use: everything but a read runs alone).
func otherNoTx(kind, kw string, ts []token) bool {
	switch kind {
	case "sqlserver":
		return tsqlNoTx(kw, ts)
	case "oracle":
		return oracleNoTx(kw, ts)
	case "clickhouse":
		return !chReads[kw]
	case "snowflake":
		return snowflakeNoTx(ts)
	}
	return false
}

// otherPlaceholders is Placeholders for SQL Server, Oracle and ClickHouse.
func otherPlaceholders(kind string, toks [][]token) (int, bool) {
	switch kind {
	case "oracle":
		return oraclePlaceholders(toks)
	case "clickhouse":
		return clickhousePlaceholders(toks)
	}
	return tsqlPlaceholders(toks)
}

// tsqlNoTx reports statements SQL Server refuses inside a transaction.
func tsqlNoTx(kw string, ts []token) bool {
	second := ""
	if len(ts) > 1 {
		second = ts[1].word
	}
	switch kw {
	case "BACKUP", "RESTORE", "RECONFIGURE", "SHUTDOWN":
		return true
	case "CREATE", "ALTER", "DROP":
		return second == "DATABASE" || second == "FULLTEXT" || kw == "ALTER" && second == "SERVER"
	}
	return false
}

// tsqlPlaceholders counts @p1, @p2, ... (go-mssqldb passes --arg values
// by those names). Other @names are variables komando cannot count.
func tsqlPlaceholders(toks [][]token) (int, bool) {
	n := 0
	for _, ts := range toks {
		for i, t := range ts {
			if t.punct != '@' || i > 0 && ts[i-1].punct == '@' && ts[i-1].pos == t.pos-1 {
				continue
			}
			if i+1 >= len(ts) || ts[i+1].pos != t.pos+1 {
				continue
			}
			next := ts[i+1]
			if next.punct == '@' { // @@ROWCOUNT
				continue
			}
			k, err := strconv.Atoi(strings.TrimPrefix(next.word, "P"))
			if !strings.HasPrefix(next.word, "P") || err != nil || k < 1 {
				return 0, false
			}
			n = max(n, k)
		}
	}
	return n, true
}

// PlanOnly is plan for SQL that SQL Server or Oracle only plans (SET
// SHOWPLAN_TEXT ON, EXPLAIN PLAN; db explain): a statement that the
// rollback would undo reads, and so does Oracle DDL that EXPLAIN PLAN takes.
// Statements that may act outside the transaction keep their rating.
func PlanOnly(plan SQLPlan) SQLPlan {
	plan.Risk = RiskRead
	lowered := true
	for i, s := range plan.Statements {
		if plan.kind == "oracle" && s.NoTx && !s.NoRollback && oracleExplainable(s.SQL) {
			s.NoTx = false // EXPLAIN PLAN does not run it, so nothing commits
			plan.Statements[i] = s
		}
		if s.NoTx || s.NoRollback {
			lowered = false
			plan.Risk = max(plan.Risk, s.Risk)
			continue
		}
		plan.Statements[i].Risk = RiskRead
	}
	if lowered {
		plan.RuleIDs, plan.Reasons = nil, nil
	}
	return plan
}
