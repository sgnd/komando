package driver

import (
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
	{"sql-server-file", "writes a file on the database server"},
	{"sql-kill", "kills sessions or shuts the server down"},
	{"sql-vacuum-full", "VACUUM FULL locks and rewrites tables"},
	{"sql-server-config", "changes server-wide configuration"},
}

// SQLRules lists the rules ClassifySQL can report.
func SQLRules() []Rule { return append([]Rule(nil), sqlRules...) }

func sqlRule(id string) Rule {
	for _, r := range sqlRules {
		if r.ID == id {
			return r
		}
	}
	return Rule{ID: id}
}

// Statement is one classified SQL statement.
type Statement struct {
	SQL     string `json:"sql"`
	Keyword string `json:"keyword"`
	Risk    Risk   `json:"risk"`
	Rows    bool   `json:"-"`                 // returns a result set (SELECT, RETURNING, SHOW, ...)
	NoTx    bool   `json:"no_tx,omitempty"`   // cannot run inside a transaction, so cannot be rolled back
	Unknown bool   `json:"unknown,omitempty"` // keyword not recognised; rated write to be safe
}

// SQLPlan is the result of ClassifySQL: the statements and the overall
// verdict (the highest risk of any statement).
type SQLPlan struct {
	Statements []Statement `json:"statements"`
	Verdict
}

type token struct {
	word  string // upper-cased keyword or identifier; "" for punctuation
	punct byte
	depth int
	pos   int // byte offset in the statement
}

// Dialects differ in quoting: MySQL uses backslash escapes and backticks,
// Postgres has E” strings and dollar quoting, SQLite accepts [names].
type dialect struct {
	backslash, dollar, backtick, bracket bool
}

var dialects = map[string]dialect{
	"postgres": {dollar: true},
	"mysql":    {backslash: true, backtick: true},
	"sqlite":   {backtick: true, bracket: true},
}

// splitSQL tokenises sql, dropping comments and quoted text, and splits it
// into statements at top-level semicolons.
func splitSQL(sql string, d dialect) (stmts []string, toks [][]token, err error) {
	var cur []token
	start, depth := 0, 0
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
		case c == '-' && i+1 < n && sql[i+1] == '-', c == '#' && d.backslash:
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
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
			esc := d.backslash || (c == '\'' && i > 0 && (sql[i-1] == 'E' || sql[i-1] == 'e') && (i < 2 || !isWord(sql[i-2])))
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
			if c != '\'' { // quoted identifier: keep as a word so it is not a keyword
				cur = append(cur, token{word: "\x00ident", depth: depth, pos: i - start})
			} else {
				cur = append(cur, token{punct: '\'', depth: depth, pos: i - start})
			}
			i = j + 1
		case c == '$' && d.dollar && (i == 0 || !isWord(sql[i-1])):
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
				cur = append(cur, token{punct: '\'', depth: depth, pos: i - start})
				i = j + 1 + end + len(tag)
			} else {
				i++ // $1 parameter
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
			for j < n && isWord(sql[j]) {
				j++
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
	plan := SQLPlan{Statements: []Statement{}}
	seen := map[string]bool{}
	for i, ts := range toks {
		risk, rules, err := classifyStatement(ts)
		if err != nil {
			return SQLPlan{}, err
		}
		kw := firstWord(ts)
		plan.Statements = append(plan.Statements, Statement{SQL: texts[i], Keyword: kw, Risk: risk,
			Rows: returnsRows(kw, ts), NoTx: noTx(kind, kw, ts), Unknown: !readFirst[kw] && !writeFirst[kw]})
		if risk > plan.Risk {
			plan.Risk = risk
		}
		for _, id := range rules {
			if !seen[id] {
				seen[id] = true
				plan.RuleIDs = append(plan.RuleIDs, id)
				plan.Reasons = append(plan.Reasons, sqlRule(id).Reason)
			}
		}
	}
	return plan, nil
}

// NeedsWrite reports whether a statement is known to change something.
// Unknown statements (often typos) may still run without --write: the
// read-only transaction refuses them if they do write, and the database
// gives a better error for a typo than komando can.
func (p SQLPlan) NeedsWrite() bool {
	for _, s := range p.Statements {
		if s.Risk > RiskRead && !s.Unknown {
			return true
		}
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
		switch kw {
		case "CREATE", "ALTER", "DROP", "RENAME", "TRUNCATE", "GRANT", "REVOKE", "LOCK", "UNLOCK", "INSTALL", "UNINSTALL", "OPTIMIZE", "REPAIR", "ANALYZE", "FLUSH", "RESET", "LOAD":
			return true
		}
	case "sqlite":
		return kw == "VACUUM"
	}
	return false
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
	"PG_TERMINATE_BACKEND": "sql-kill",
	"PG_CANCEL_BACKEND":    "sql-kill",
	"PG_RELOAD_CONF":       "sql-server-config",
	"PG_PROMOTE":           "sql-kill",
	"LO_EXPORT":            "sql-server-file",
	"DBLINK_EXEC":          "sql-program",
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
		if t.depth == 0 && t.word != "" && (readFirst[t.word] && t.word != "EXPLAIN" && t.word != "SET" || writeFirst[t.word] && t.word != "ANALYZE") {
			return ts[i:], analyze
		}
	}
	return nil, analyze
}

func classifyStatement(ts []token) (Risk, []string, error) {
	first := firstWord(ts)
	second := ""
	if len(ts) > 1 {
		second = ts[1].word
	}
	if txControl[first] && (first != "START" || second == "TRANSACTION") {
		return 0, nil, out.Errf(out.ExitUsage, "SQL_TX_CONTROL",
			"leave transactions to komando: without --write it runs a read-only transaction, with --write one transaction that --dry-run rolls back",
			"%s is not allowed in komando db", first)
	}
	if first == "EXPLAIN" {
		inner, analyze := explainTarget(ts)
		if !analyze || inner == nil {
			return RiskRead, nil, nil // plain EXPLAIN only plans
		}
		return classifyStatement(inner)
	}
	risk := RiskWrite
	if readFirst[first] {
		risk = RiskRead
	}
	if first == "PRAGMA" && hasPunct(ts, '=') {
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
		if second == "ROLE" || second == "USER" {
			flag("sql-privileges")
		}
		if first == "ALTER" && second == "SYSTEM" {
			flag("sql-server-config")
		}
	case "SET":
		switch second {
		case "PASSWORD":
			flag("sql-privileges")
		case "GLOBAL", "PERSIST", "PERSIST_ONLY":
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
		default:
			if id, ok := dangerousFuncs[t.word]; ok && i+1 < len(ts) && ts[i+1].punct == '(' {
				flag(id)
			}
		}
	}
	return risk, rules, nil
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
