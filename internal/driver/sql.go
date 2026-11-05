package driver

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/sgnd/komando/internal/out"
)

// SQL classification is the second safety layer for `komando db`. The first
// is the database itself: queries without --write run in a read-only
// transaction, so a statement this code misjudges is still refused there.
// The classifier exists to give a clear error before anything is sent, and
// to tell write from destructive for --write.

// Rule is a named SQL check, listed by `komando policy`.
type Rule struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

var sqlRules = []Rule{
	{"sql-drop", "drops a database object or column"},
	{"sql-truncate", "empties a table"},
	{"sql-delete-no-where", "DELETE without WHERE removes every row"},
	{"sql-update-no-where", "UPDATE without WHERE changes every row"},
	{"sql-privileges", "changes users, roles or privileges"},
	{"sql-program", "runs a program on the database server (COPY ... PROGRAM)"},
	{"sql-server-file", "reads or writes files on the database server"},
	{"sql-kill", "kills sessions or shuts the server down"},
	{"sql-vacuum-full", "VACUUM FULL locks and rewrites tables"},
	{"sql-server-config", "changes server-wide configuration"},
	{"sql-session-config", "changes a setting whose name komando cannot see (set_config with a computed name)"},
	{"sql-opaque", "runs code komando cannot inspect (DO, CALL, PREPARE/EXECUTE)"},
	{"sql-remote", "runs SQL over another connection that the read-only transaction does not cover (dblink)"},
	{"db-restore", "restoring a backup can overwrite existing data"},
}

var dataRules = []Rule{
	{"data-delete", "deletes data that cannot be recovered (cache keys, stored objects)"},
}

// DataRules lists rules for named delete actions (cache rm, storage rm).
func DataRules() []Rule { return append([]Rule(nil), dataRules...) }

// DataDelete is the verdict for deleting cache keys or stored objects.
func DataDelete() Verdict {
	return Verdict{Risk: RiskDestructive, RuleIDs: []string{"data-delete"}, Reasons: []string{dataRules[0].Reason}}
}

// SQLRules lists the rules ClassifySQL can report.
func SQLRules() []Rule { return append([]Rule(nil), sqlRules...) }

// RuleReason is the human explanation of a rule ID.
func RuleReason(id string) string {
	for _, r := range sqlRules {
		if r.ID == id {
			return r.Reason
		}
	}
	return id
}

// Statement is one classified SQL statement.
type Statement struct {
	SQL        string `json:"sql"`
	Keyword    string `json:"keyword"`
	Risk       Risk   `json:"risk"`
	Rows       bool   `json:"-"`                     // returns a result set (SELECT, RETURNING, SHOW, ...)
	NoTx       bool   `json:"no_tx,omitempty"`       // cannot run inside a transaction, so cannot be rolled back
	NoRollback bool   `json:"no_rollback,omitempty"` // runs in the transaction, but a rollback may not undo it (setval, DO, COPY ... PROGRAM)
	Unknown    bool   `json:"unknown,omitempty"`     // keyword not recognised; rated write to be safe
}

// SQLPlan is the result of ClassifySQL: the statements and the overall
// verdict (the highest risk of any statement).
type SQLPlan struct {
	Statements []Statement `json:"statements"`
	Verdict
	kind string
}

type token struct {
	word  string // upper-cased keyword or identifier; "" for punctuation
	ident string // upper-cased content of a quoted identifier ("pg_terminate_backend")
	punct byte
	str   string // content of a string literal (punct '\'')
	esc   bool   // the string takes escapes (E'...', U&'...'), so str is not its real value
	depth int
	pos   int // byte offset in the statement
}

// Dialects differ in quoting: MySQL uses backslash escapes and backticks,
// Postgres has E” strings and dollar quoting, SQLite accepts [names].
// Each difference from the server's own scanner is a way to hide SQL, so
// these follow the servers' lexers, not the SQL standard.
type dialect struct {
	backslash, dollar, backtick, bracket bool
	execComments                         bool // MySQL runs the text inside /*! ... */
	dashSpace                            bool // MySQL: "--" starts a comment only before white space or a control character ("1 --1" is 1 - -1)
	crComments                           bool // Postgres: a -- comment ends at \r as well as \n
	execAsCode                           bool // restore: read /*! ... */ as the code MySQL runs instead of refusing it
	unicodeEsc                           bool // Postgres: U&"..." names and U&'...' strings take \XXXX escapes
}

var dialects = map[string]dialect{
	"postgres": {dollar: true, crComments: true, unicodeEsc: true},
	"mysql":    {backslash: true, backtick: true, execComments: true, dashSpace: true},
	"sqlite":   {backtick: true, bracket: true},
}

// nameByte reports whether c continues an unquoted name. Postgres names
// may contain $ (x$1), so there a $ inside a name starts no quote.
func (d dialect) nameByte(c byte) bool {
	return isWord(c) || d.dollar && c == '$'
}

// splitSQL tokenises sql, dropping comments and quoted text, and splits it
// into statements at top-level semicolons.
func splitSQL(sql string, d dialect) (stmts []string, toks [][]token, err error) {
	var cur []token
	start, depth := 0, 0
	inExec := false // inside /*! ... */ (execAsCode)
	flush := func(end int) {
		text := strings.TrimSpace(sql[start:end])
		if len(cur) > 0 {
			stmts = append(stmts, text)
			toks = append(toks, cur)
		}
		cur = nil
	}
	n := len(sql)
	for i := 0; i < n; {
		c := sql[i]
		switch {
		case inExec && c == '*' && i+1 < n && sql[i+1] == '/':
			inExec = false
			i += 2
		case d.dashSpace && c == '-' && i+2 < n && sql[i+1] == '-' && sql[i+2] > 0x7f:
			// MySQL asks the connection's character set whether this byte is
			// a space or a control character, so komando cannot know
			return nil, nil, out.Errf(out.ExitUsage, "SQL_HIDDEN_CODE",
				"put a space after -- to start a comment: whether this one starts a comment depends on the server's character set",
				"-- is followed by a non-ASCII byte")
		case c == '-' && i+1 < n && sql[i+1] == '-' && (!d.dashSpace || i+2 >= n || sql[i+2] <= ' ' || sql[i+2] == 0x7f), c == '#' && d.backslash:
			// MySQL: a control character (0x7f too) counts as white space here
			for i < n && sql[i] != '\n' && !(d.crComments && sql[i] == '\r') {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
			if d.execComments && i+2 < n && (sql[i+2] == '!' || sql[i+2] == 'M' && i+3 < n && sql[i+3] == '!') {
				if d.execAsCode && !inExec { // the marker and its version number go; the code stays
					i += 3
					if sql[i-1] == 'M' {
						i++
					}
					for i < n && sql[i] >= '0' && sql[i] <= '9' {
						i++
					}
					inExec = true
					continue
				}
				return nil, nil, out.Errf(out.ExitUsage, "SQL_HIDDEN_CODE",
					"write the statement without /*! ... */: MySQL runs what is inside, so komando cannot check it",
					"executable comments (/*! ... */) are not allowed")
			}
			level := 0
			for i < n {
				if i+1 < n && sql[i] == '/' && sql[i+1] == '*' {
					level++
					i += 2
				} else if i+1 < n && sql[i] == '*' && sql[i+1] == '/' {
					level--
					i += 2
					if level == 0 || !d.dollar { // only Postgres nests comments
						break
					}
				} else {
					i++
				}
			}
			if level > 0 && d.dollar {
				return nil, nil, out.Usage("unterminated /* comment in SQL")
			}
		case c == '\'' || c == '"' || (c == '`' && d.backtick) || (c == '[' && d.bracket):
			closeCh := c
			if c == '[' {
				closeCh = ']'
			}
			// a prefix counts only where it starts a token: xE'...' is the name xE and a plain string
			prefix := func(p string) bool {
				k := i - len(p)
				return k >= 0 && strings.EqualFold(sql[k:i], p) && (k == 0 || !d.nameByte(sql[k-1]))
			}
			uEsc := d.unicodeEsc && prefix("U&")
			if uEsc && c == '"' {
				return nil, nil, out.Errf(out.ExitUsage, "SQL_HIDDEN_CODE",
					`write the name without U& escapes (U&"\0064blink" is dblink): komando cannot check a name it cannot read`,
					`U&"..." names are not allowed`)
			}
			// MySQL escapes with backslash only inside '' and "", never in `names`;
			// Postgres only inside E'...'
			esc := d.backslash && c != '`' || c == '\'' && d.dollar && prefix("E")
			j := i + 1
			for ; j < n; j++ {
				if esc && sql[j] == '\\' {
					j++
					continue
				}
				if sql[j] == closeCh {
					if j+1 < n && sql[j+1] == closeCh && closeCh != ']' {
						j++
						continue
					}
					break
				}
			}
			if j >= n {
				return nil, nil, out.Usage("unterminated %c quote in SQL", c)
			}
			if c != '\'' { // quoted identifier: never a keyword, but still a function name
				name := sql[i+1 : j]
				if closeCh != ']' {
					name = strings.ReplaceAll(name, string(closeCh)+string(closeCh), string(closeCh))
				}
				cur = append(cur, token{word: "\x00ident", ident: strings.ToUpper(name), depth: depth, pos: i - start})
			} else {
				cur = append(cur, token{punct: '\'', str: strings.ReplaceAll(sql[i+1:j], "''", "'"), esc: esc || uEsc, depth: depth, pos: i - start})
			}
			i = j + 1
		case c == '$' && d.dollar: // names swallow their own $ (below), so this starts a token
			j := i + 1
			for j < n && (isWord(sql[j]) && !unicode.IsDigit(rune(sql[j])) || j > i+1 && isWord(sql[j])) {
				j++
			}
			if j < n && sql[j] == '$' {
				tag := sql[i : j+1]
				end := strings.Index(sql[j+1:], tag)
				if end < 0 {
					return nil, nil, out.Usage("unterminated %s quote in SQL", tag)
				}
				cur = append(cur, token{punct: '\'', str: sql[j+1 : j+1+end], depth: depth, pos: i - start})
				i = j + 1 + end + len(tag)
			} else {
				cur = append(cur, token{punct: '$', depth: depth, pos: i - start}) // $1 parameter
				i++
			}
		case c == ';' && depth == 0:
			flush(i)
			i++
			start = i
		case c == '(':
			cur = append(cur, token{punct: c, depth: depth, pos: i - start})
			depth++
			i++
		case c == ')':
			if depth > 0 {
				depth--
			}
			cur = append(cur, token{punct: c, depth: depth, pos: i - start})
			i++
		case isWord(c):
			j := i
			number := c >= '0' && c <= '9' // 1$$x$$ is 1 and a dollar quote; x$$ is one name
			for j < n && (isWord(sql[j]) || !number && d.nameByte(sql[j])) {
				j++
			}
			if number && d.dollar && j < n && sql[j] == '$' && strings.Trim(sql[i:j], "0123456789") != "" {
				// 1abc$$ is 1 and the name abc$$ before Postgres 15, a dollar
				// quote after 0x1f or 1e5: the servers disagree, so refuse it
				return nil, nil, out.Errf(out.ExitUsage, "SQL_HIDDEN_CODE",
					"put a space between a number and the name or $ after it: Postgres versions read this differently, so komando cannot check it",
					"%s$ is ambiguous", strings.ToLower(sql[i:j]))
			}
			cur = append(cur, token{word: strings.ToUpper(sql[i:j]), depth: depth, pos: i - start})
			i = j
		case unicode.IsSpace(rune(c)):
			i++
		default:
			cur = append(cur, token{punct: c, depth: depth, pos: i - start})
			i++
		}
	}
	flush(n)
	return stmts, toks, nil
}

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// ClassifySQL splits sql into statements and classifies each one. kind is
// a conn kind (postgres, mysql, sqlite). Transaction control (BEGIN,
// COMMIT, ...) is refused: komando owns the transaction, and a COMMIT inside
// a dry run would make it real.
func ClassifySQL(kind, sql string) (SQLPlan, error) {
	d, ok := dialects[kind]
	if !ok {
		return SQLPlan{}, out.Usage("%s conns do not take SQL", kind)
	}
	texts, toks, err := splitSQL(sql, d)
	if err != nil {
		return SQLPlan{}, err
	}
	if len(texts) == 0 {
		return SQLPlan{}, out.Usage("no SQL statement given")
	}
	plan := SQLPlan{Statements: []Statement{}, kind: kind}
	seen := map[string]bool{}
	for i, ts := range toks {
		risk, rules, err := classifyStatement(ts, true)
		if err != nil {
			return SQLPlan{}, err
		}
		kw := firstWord(ts)
		plan.Statements = append(plan.Statements, Statement{SQL: texts[i], Keyword: kw, Risk: risk,
			Rows: returnsRows(kw, ts), NoTx: noTx(kind, kw, ts), NoRollback: noRollback(kw, ts, rules),
			Unknown: !readFirst[kw] && !writeFirst[kw] && !opaqueFirst[kw]})
		if risk > plan.Risk {
			plan.Risk = risk
		}
		for _, id := range rules {
			if !seen[id] {
				seen[id] = true
				plan.RuleIDs = append(plan.RuleIDs, id)
				plan.Reasons = append(plan.Reasons, RuleReason(id))
			}
		}
	}
	return plan, nil
}

// NeedsWrite reports whether a statement must not run without --write.
// Unknown statements (often typos) that are not otherwise flagged may run
// in PostgreSQL and SQLite, whose read-only mode refuses them if they do
// write, and whose error for a typo is clearer than komando's. MySQL's
// read-only transaction does not cover admin statements, so there an
// unknown statement needs --write.
func (p SQLPlan) NeedsWrite() bool {
	for _, s := range p.Statements {
		if s.Risk == RiskRead || s.Unknown && s.Risk == RiskWrite && p.kind != "mysql" {
			continue
		}
		return true
	}
	return false
}

func returnsRows(kw string, ts []token) bool {
	switch kw {
	case "SET", "USE":
		return false
	case "PRAGMA":
		return !hasPunct(ts, '=')
	}
	return readFirst[kw] || hasWord(ts, "RETURNING")
}

// noTx reports statements that cannot run inside a transaction block (or,
// in MySQL, commit it implicitly). They can never be rolled back.
func noTx(kind, kw string, ts []token) bool {
	second := ""
	if len(ts) > 1 {
		second = ts[1].word
	}
	switch kind {
	case "postgres":
		switch kw {
		case "VACUUM":
			return true
		case "CREATE", "DROP", "ALTER":
			if second == "DATABASE" || second == "TABLESPACE" || second == "SYSTEM" || second == "SUBSCRIPTION" {
				return true
			}
		}
		return (kw == "CREATE" || kw == "DROP" || kw == "REINDEX") && hasWord(ts, "CONCURRENTLY")
	case "mysql":
		// MySQL commits implicitly before (and after) many statements, and
		// new ones come with new versions (IMPORT TABLE, CLONE, BACKUP
		// STAGE), so only statements known to stay in the transaction run
		// in it. Everything else must be sent alone.
		if kw == "SET" { // SET PASSWORD and SET DEFAULT ROLE write the mysql tables and commit
			return second == "PASSWORD" || second == "DEFAULT" && len(ts) > 2 && ts[2].word == "ROLE"
		}
		return !mysqlInTx[kw]
	case "sqlite":
		return kw == "VACUUM"
	}
	return false
}

// mysqlInTx are the MySQL statements that do not commit implicitly.
var mysqlInTx = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true, "REPLACE": true, "WITH": true,
	"VALUES": true, "TABLE": true, "SHOW": true, "DESCRIBE": true, "DESC": true, "EXPLAIN": true,
	"HELP": true, "USE": true, "DO": true, "HANDLER": true,
}

func firstWord(ts []token) string {
	for _, t := range ts {
		if t.word != "" {
			return t.word
		}
	}
	return ""
}

var readFirst = map[string]bool{
	"SELECT": true, "SHOW": true, "DESCRIBE": true, "DESC": true, "VALUES": true, "TABLE": true,
	"EXPLAIN": true, "WITH": true, "PRAGMA": true, "SET": true, "USE": true, "HELP": true,
}

var txControl = map[string]bool{
	"BEGIN": true, "START": true, "COMMIT": true, "END": true, "ROLLBACK": true, "ABORT": true,
	"SAVEPOINT": true, "RELEASE": true,
}

// dangerousFuncs have side effects a read-only transaction does not stop.
var dangerousFuncs = map[string]string{
	"PG_TERMINATE_BACKEND": "sql-kill", "PG_CANCEL_BACKEND": "sql-kill", "PG_PROMOTE": "sql-kill",
	"PG_RELOAD_CONF": "sql-server-config", "PG_ROTATE_LOGFILE": "sql-server-config", "PG_SWITCH_WAL": "sql-server-config",
	"PG_CREATE_RESTORE_POINT": "sql-server-config", "PG_WAL_REPLAY_PAUSE": "sql-server-config", "PG_WAL_REPLAY_RESUME": "sql-server-config",
	"PG_DROP_REPLICATION_SLOT": "sql-server-config", "PG_CREATE_PHYSICAL_REPLICATION_SLOT": "sql-server-config",
	"PG_CREATE_LOGICAL_REPLICATION_SLOT": "sql-server-config", "PG_STAT_RESET": "sql-server-config",
	"LO_EXPORT": "sql-server-file", "LO_IMPORT": "sql-server-file", "PG_READ_FILE": "sql-server-file",
	"PG_READ_BINARY_FILE": "sql-server-file", "PG_FILE_WRITE": "sql-server-file", "PG_FILE_UNLINK": "sql-server-file",
	"PG_FILE_RENAME": "sql-server-file", "PG_FILE_SYNC": "sql-server-file", "PG_STAT_FILE": "sql-server-file",
	"PG_LOGDIR_LS": "sql-server-file", "PG_CURRENT_LOGFILE": "sql-server-file", "LOAD_FILE": "sql-server-file",
	"SYS_EXEC": "sql-program", "SYS_EVAL": "sql-program",
}

// funcRule rates a function call by name; prefixes cover function families.
func funcRule(name string) (string, bool) {
	if id, ok := dangerousFuncs[name]; ok {
		return id, true
	}
	switch {
	case strings.HasPrefix(name, "DBLINK"):
		return "sql-remote", true
	case strings.HasPrefix(name, "PG_STAT_RESET"), strings.HasPrefix(name, "PG_REPLICATION_ORIGIN_"):
		return "sql-server-config", true
	case strings.HasPrefix(name, "PG_LS_"): // pg_ls_dir, pg_ls_waldir, pg_ls_tmpdir, ...: list server directories
		return "sql-server-file", true
	}
	return "", false
}

// writeFuncs change data. The read-only transaction refuses them, but
// rating them write gives the clear error first, and makes --write on a
// protected conn ask, the same as UPDATE.
var writeFuncs = map[string]bool{
	"NEXTVAL": true, "SETVAL": true, // sequences (Postgres, MariaDB)
	"LO_UNLINK": true, "LO_PUT": true, "LO_CREATE": true, "LO_CREAT": true, "LO_FROM_BYTEA": true, // large objects
	"LO_TRUNCATE": true, "LO_TRUNCATE64": true, "LOWRITE": true,
}

// noRollbackFuncs change something a rollback does not undo, so a dry run
// must not call them. (nextval is left alone: an INSERT advances the
// sequence the same way.)
var noRollbackFuncs = map[string]bool{"SETVAL": true}

// noRollbackRules match statements whose effect a rollback does not undo:
// a killed session, a program run or a file written on the server, a
// commit on another server (dblink), or code komando cannot see into.
var noRollbackRules = map[string]bool{
	"sql-kill": true, "sql-program": true, "sql-server-file": true, "sql-server-config": true,
	"sql-remote": true, "sql-opaque": true, "sql-session-config": true,
}

// noRollback reports a statement that runs inside the transaction but
// whose effect a rollback may not undo, so a dry run must not execute it.
func noRollback(kw string, ts []token, rules []string) bool {
	if opaqueFirst[kw] || callsAny(ts, noRollbackFuncs) {
		return true
	}
	for _, id := range rules {
		if noRollbackRules[id] {
			return true
		}
	}
	return false
}

// callsAny reports whether ts calls one of the functions in names.
func callsAny(ts []token, names map[string]bool) bool {
	for i, t := range ts {
		if i+1 < len(ts) && ts[i+1].punct == '(' && (names[t.word] || names[t.ident]) {
			return true
		}
	}
	return false
}

// readPragmas are SQLite pragmas whose argument (a table or index name)
// only says what to read. Any other pragma given a value, as name = value
// or name(value), changes a setting.
var readPragmas = map[string]bool{
	"TABLE_INFO": true, "TABLE_XINFO": true, "TABLE_LIST": true, "INDEX_LIST": true, "INDEX_INFO": true,
	"INDEX_XINFO": true, "FOREIGN_KEY_LIST": true, "FOREIGN_KEY_CHECK": true, "INTEGRITY_CHECK": true, "QUICK_CHECK": true,
}

// pragmaWrites reports whether a PRAGMA statement changes something.
func pragmaWrites(ts []token) bool {
	if hasPunct(ts, '=') {
		return true
	}
	for i := 1; i < len(ts); i++ {
		name := ts[i].word
		if ts[i].ident != "" {
			name = ts[i].ident
		}
		switch {
		case name == "" || i+1 < len(ts) && ts[i+1].punct == '.': // [schema.]name
			continue
		case name == "OPTIMIZE" || name == "INCREMENTAL_VACUUM" || name == "WAL_CHECKPOINT":
			return true // they work on the file even without a value
		}
		return i+1 < len(ts) && ts[i+1].punct == '(' && !readPragmas[name]
	}
	return false
}

// opaqueFirst are statements whose real effect is hidden from komando.
var opaqueFirst = map[string]bool{"DO": true, "CALL": true, "PREPARE": true, "EXECUTE": true, "EXEC": true}

// stringRules are settings that change how SQL text is parsed. komando's
// checks assume the defaults, so changing them is refused.
// txSettings would switch off the read-only transaction komando runs (SET
// TRANSACTION READ WRITE) or commit it early (SET autocommit in MySQL).
var txSettings = map[string]bool{
	"TRANSACTION": true, "CHARACTERISTICS": true, "TRANSACTION_READ_ONLY": true, "DEFAULT_TRANSACTION_READ_ONLY": true,
	"TX_READ_ONLY": true, "AUTOCOMMIT": true, "COMPLETION_TYPE": true,
}

// The client character set counts too: the server converts the text from
// it before reading it, and in SJIS, GBK or BIG5 a backslash (0x5c) can be
// the second byte of a character (SET NAMES, SET CHARACTER SET, SET
// client_encoding, set_config('client_encoding', ...)).
var stringRules = map[string]bool{
	"STANDARD_CONFORMING_STRINGS": true, "BACKSLASH_QUOTE": true, "ESCAPE_STRING_WARNING": true, "SQL_MODE": true,
	"CLIENT_ENCODING": true, "NAMES": true, "CHARACTER_SET_CLIENT": true, "CHARSET": true, "CHARACTER": true,
}

// writeFirst are statements that change something when they lead.
var writeFirst = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true, "REPLACE": true, "UPSERT": true,
	"CREATE": true, "ALTER": true, "DROP": true, "TRUNCATE": true, "RENAME": true, "COMMENT": true,
	"COPY": true, "CALL": true, "DO": true, "LOCK": true, "GRANT": true, "REVOKE": true, "REINDEX": true,
	"CLUSTER": true, "VACUUM": true, "ANALYZE": true, "REFRESH": true, "LOAD": true, "FLUSH": true,
	"RESET": true, "ATTACH": true, "DETACH": true, "IMPORT": true, "INSTALL": true, "UNINSTALL": true,
	"KILL": true, "SHUTDOWN": true, "OPTIMIZE": true, "REPAIR": true, "PURGE": true, "CHECKPOINT": true,
}

// explainTarget returns the statement EXPLAIN describes and whether it is
// executed (ANALYZE).
func explainTarget(ts []token) ([]token, bool) {
	analyze := false
	for i := 1; i < len(ts); i++ {
		t := ts[i]
		if t.word == "ANALYZE" || t.word == "ANALYSE" {
			analyze = true
		}
		if t.depth == 0 && t.word != "" && (readFirst[t.word] && t.word != "EXPLAIN" && t.word != "SET" || writeFirst[t.word] && t.word != "ANALYZE" || opaqueFirst[t.word]) {
			return ts[i:], analyze
		}
	}
	return nil, analyze
}

// classifyStatement rates one statement. strict (komando db) refuses
// transaction control and changes to the settings komando's checks rely
// on; a restore (not strict) checks those itself and only wants the rules.
func classifyStatement(ts []token, strict bool) (Risk, []string, error) {
	first := firstWord(ts)
	second := ""
	if len(ts) > 1 {
		second = ts[1].word
	}
	if txControl[first] && (first != "START" || second == "TRANSACTION") {
		if !strict {
			return RiskWrite, nil, nil
		}
		return 0, nil, out.Errf(out.ExitUsage, "SQL_TX_CONTROL",
			"leave transactions to komando: without --write it runs a read-only transaction, with --write one transaction that --dry-run rolls back",
			"%s is not allowed in komando db", first)
	}
	if first == "EXPLAIN" {
		inner, analyze := explainTarget(ts)
		switch {
		case inner == nil && analyze:
			return RiskWrite, nil, nil // runs something komando does not know
		case inner == nil, !analyze && !opaqueFirst[firstWord(inner)]:
			return RiskRead, nil, nil // plain EXPLAIN only plans
		}
		return classifyStatement(inner, strict) // EXPLAIN EXECUTE runs its argument expressions even without ANALYZE
	}
	if strict && (first == "SET" || first == "RESET") {
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
				return 0, nil, out.Errf(out.ExitUsage, "SQL_HIDDEN_CODE",
					"write the setting name without quotes or backslashes: komando cannot check a name it cannot read",
					"setting name %s has escapes", strings.ToLower(name))
			}
			if err := settingAllowed(name); err != nil {
				return 0, nil, err
			}
		}
	}
	risk := RiskWrite
	if readFirst[first] {
		risk = RiskRead
	}
	if first == "PRAGMA" && pragmaWrites(ts) {
		risk = RiskWrite
	}
	var rules []string
	flag := func(id string) {
		rules = append(rules, id)
		risk = RiskDestructive
	}
	word := func(i int) string {
		if i >= 0 && i < len(ts) {
			return ts[i].word
		}
		return ""
	}
	switch first {
	case "DROP":
		flag("sql-drop")
	case "TRUNCATE":
		flag("sql-truncate")
	case "GRANT", "REVOKE":
		flag("sql-privileges")
	case "CREATE", "ALTER", "RENAME":
		if second == "ROLE" || second == "USER" || second == "DEFAULT" && first == "ALTER" {
			flag("sql-privileges")
		}
		if first == "ALTER" && second == "SYSTEM" {
			flag("sql-server-config")
		}
	case "SET":
		if second == "PASSWORD" || second == "DEFAULT" && word(2) == "ROLE" { // MySQL: SET DEFAULT ROLE ... TO user
			flag("sql-privileges")
		}
		if hasWord(ts, "GLOBAL") || hasWord(ts, "PERSIST") || hasWord(ts, "PERSIST_ONLY") { // also @@global.x
			flag("sql-server-config")
		}
	case "DO", "CALL", "PREPARE", "EXECUTE", "EXEC":
		flag("sql-opaque")
	case "STOP", "CHANGE", "PURGE":
		flag("sql-server-config") // MySQL replication and binary logs
	case "START":
		if second != "TRANSACTION" {
			flag("sql-server-config")
		}
	case "KILL", "SHUTDOWN":
		flag("sql-kill")
	case "VACUUM":
		if second == "FULL" || hasWord(ts, "FULL") {
			flag("sql-vacuum-full")
		}
	case "COPY":
		if hasWord(ts, "PROGRAM") {
			flag("sql-program")
		}
		for i, t := range ts { // COPY t TO '/file' or FROM '/file' (not STDIN/STDOUT)
			if (t.word == "TO" || t.word == "FROM") && t.depth == 0 && i+1 < len(ts) && ts[i+1].punct == '\'' {
				flag("sql-server-file")
				break
			}
		}
	}
	for i, t := range ts {
		switch t.word {
		case "DROP":
			if first == "ALTER" && t.depth == 0 {
				flag("sql-drop") // ALTER TABLE ... DROP COLUMN
			}
		case "INSERT", "MERGE":
			risk = max(risk, RiskWrite)
		case "DELETE", "UPDATE":
			prev := word(i - 1)
			if prev == "ON" || prev == "FOR" || prev == "KEY" || prev == "\x00ident" {
				continue // ON DELETE CASCADE, FOR UPDATE, ON DUPLICATE KEY UPDATE
			}
			risk = max(risk, RiskWrite)
			if prev == "DO" && t.word == "UPDATE" {
				continue // ON CONFLICT DO UPDATE only touches the conflicting row
			}
			if !hasWhere(ts, i) {
				flag(map[string]string{"DELETE": "sql-delete-no-where", "UPDATE": "sql-update-no-where"}[t.word])
			}
		case "INTO":
			switch word(i + 1) {
			case "OUTFILE", "DUMPFILE":
				flag("sql-server-file")
			default:
				if first == "SELECT" && t.depth == 0 {
					risk = max(risk, RiskWrite) // SELECT ... INTO creates a table (Postgres)
				}
			}
		case "NEXT":
			if word(i+1) == "VALUE" && word(i+2) == "FOR" { // MariaDB: NEXT VALUE FOR seq
				risk = max(risk, RiskWrite)
			}
		default:
			name := t.word
			if t.ident != "" {
				name = t.ident
			}
			if i+1 >= len(ts) || ts[i+1].punct != '(' {
				continue
			}
			if name == "SET_CONFIG" {
				// set_config changes a setting of this session (or, with true, of
				// this transaction) only; komando's session ends with the command.
				// Like SET, it must not touch the transaction or string rules.
				// A name in E'...' or U&'...' may be spelled with escapes komando
				// does not decode, so it counts as a name komando cannot see.
				if i+3 < len(ts) && ts[i+2].punct == '\'' && !ts[i+2].esc && ts[i+3].punct == ',' {
					if !strict {
						continue
					}
					if err := settingAllowed(strings.ToUpper(strings.TrimSpace(ts[i+2].str))); err != nil {
						return 0, nil, err
					}
				} else {
					flag("sql-session-config")
				}
				continue
			}
			if id, ok := funcRule(name); ok {
				flag(id)
			}
			if writeFuncs[name] {
				risk = max(risk, RiskWrite)
			}
		}
	}
	return risk, rules, nil
}

// settingAllowed refuses changes to the settings komando's own safety
// depends on: the transaction mode and the string rules. name is upper case.
func settingAllowed(name string) error {
	if txSettings[name] {
		return out.Errf(out.ExitUsage, "SQL_TX_CONTROL",
			"leave transactions to komando: without --write it runs a read-only transaction, with --write one transaction that --dry-run rolls back",
			"changing %s is not allowed in komando db", strings.ToLower(name))
	}
	if stringRules[name] {
		return out.Errf(out.ExitUsage, "SQL_STRING_RULES",
			"leave this setting alone: komando checks SQL with the server's default string rules",
			"changing %s is not allowed in komando db", strings.ToLower(name))
	}
	return nil
}

// Placeholders counts the parameters in sql ($1.. in postgres, ? in mysql
// and sqlite), outside strings and comments. ok is false when the count is
// not known (sqlite named parameters, or SQL that does not parse).
func Placeholders(kind, sql string) (n int, ok bool) {
	d, found := dialects[kind]
	if !found {
		return 0, false
	}
	_, toks, err := splitSQL(sql, d)
	if err != nil {
		return 0, false
	}
	for _, ts := range toks {
		for i, t := range ts {
			next := token{}
			if i+1 < len(ts) {
				next = ts[i+1]
			}
			adjacentNumber := next.word != "" && next.pos == t.pos+1 && strings.Trim(next.word, "0123456789") == ""
			switch {
			case kind == "postgres" && t.punct == '$' && adjacentNumber:
				k, _ := strconv.Atoi(next.word)
				n = max(n, k)
			case kind == "postgres":
			case t.punct == '?' && kind == "sqlite" && adjacentNumber: // ?NNN
				k, _ := strconv.Atoi(next.word)
				n = max(n, k)
			case t.punct == '?':
				n++
			case kind == "sqlite" && (t.punct == ':' || t.punct == '@' || t.punct == '$') && next.word != "" && next.pos == t.pos+1:
				return 0, false // named parameters
			}
		}
	}
	return n, true
}

func hasWord(ts []token, w string) bool {
	for _, t := range ts {
		if t.word == w {
			return true
		}
	}
	return false
}

func hasPunct(ts []token, c byte) bool {
	for _, t := range ts {
		if t.punct == c {
			return true
		}
	}
	return false
}

// hasWhere reports whether the DELETE/UPDATE at ts[i] has a WHERE (or, for
// Postgres, WHERE CURRENT OF) at its own nesting level before its scope ends.
func hasWhere(ts []token, i int) bool {
	d := ts[i].depth
	for _, t := range ts[i+1:] {
		if t.depth < d || t.punct == ')' && t.depth == d-1 {
			return false
		}
		if t.depth == d && t.word == "WHERE" {
			return true
		}
		// a later statement part at the same level (RETURNING, a new CTE body) ends nothing; keep scanning
	}
	return false
}
