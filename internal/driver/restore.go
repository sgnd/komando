package driver

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// psql and the mysql client obey their own commands inside a SQL file
// (`\! rm -rf /`, `system ...`, `\i other.sql`), which run on the machine
// that restores. komando restores plain SQL itself (dbx.Restore), which
// runs no client commands, and CheckRestore still reads the whole backup
// before anything is sent: it follows the file the way psql and the mysql
// client would (Lexer), refuses client commands other than the ones dumps
// themselves emit, and refuses what it cannot follow: a file that ends
// inside a quote, or a SET or set_config that changes how quotes are read.
// Code komando cannot look into (a function, DO, PREPARE) could still
// change that setting; such statements are named in the verdict.

var (
	pgRestrictLine = regexp.MustCompile(`^\\(restrict|unrestrict)[ \t]+[A-Za-z0-9]+$`)
	pgConnectLine  = regexp.MustCompile(`^\\(connect|c)\b`)
	pgCopyStdin    = regexp.MustCompile(`^COPY\b.*\bFROM\s+STDIN\b`)
	mysqlLongCmd   = regexp.MustCompile(`(?i)^\s*(system|source|connect|pager|tee|nopager|notee|edit|charset|warnings)\b`)
	mysqlDelimLine = regexp.MustCompile(`(?i)^delimiter[ \t]`)
)

// IsCopyStdin reports whether code (a statement as Lexer.Last returns it)
// is COPY ... FROM stdin, whose data lines follow it.
func IsCopyStdin(code string) bool { return pgCopyStdin.MatchString(code) }

// ParseDelimiter reads a mysql client DELIMITER line (trimmed, at the start
// of a statement). ok is false when the line is not a DELIMITER command;
// delim is "" when it is one komando does not follow: no delimiter, more
// than one word, or a quote or backslash in it.
func ParseDelimiter(trimmed string) (delim string, ok bool) {
	if !mysqlDelimLine.MatchString(trimmed) {
		return "", false
	}
	d := strings.TrimSpace(trimmed[len("delimiter"):])
	if d == "" || strings.ContainsAny(d, " \t\\'\"`") {
		return "", true
	}
	return d, true
}

// restoreRules are the SQL rules a restore names next to db-restore: what
// a file does beyond writing and dropping data.
var restoreRules = map[string]bool{
	"sql-program": true, "sql-server-file": true, "sql-server-config": true, "sql-privileges": true,
	"sql-opaque": true, "sql-remote": true, "sql-kill": true,
}

// maxInspect is the largest statement whose rules CheckRestore reads (a
// huge INSERT would cost far more memory than the file); a larger one is
// named as sql-opaque.
const maxInspect = 16 << 20

// CheckRestore reads a whole plain SQL backup. It returns an error naming
// the first line with a client command that could run code or read files
// where the restore runs, or the first place where komando cannot be sure
// how psql or mysql would read the file. Otherwise the verdict names what
// the SQL does beyond writing data (sql-program, sql-server-file, ...),
// with the line where each first appears; it is empty for an ordinary dump.
func CheckRestore(kind string, r io.Reader) (Verdict, error) {
	if kind != "postgres" && kind != "mysql" {
		return Verdict{}, out.Usage("%s conns have no SQL restore", kind)
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	l := NewLexer(kind)
	chk := newRestoreCheck(kind)
	var stmt strings.Builder // the raw text of the current statement
	stmtLine := 0
	inCopy, copyLine := false, 0
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSuffix(sc.Text(), "\r")
		if inCopy { // COPY data: backslashes are escapes, the block ends with \.
			if text == `\.` {
				inCopy = false
			}
			continue
		}
		trimmed := strings.TrimSpace(text)
		if l.Idle() && l.Empty() { // at the start of a statement
			switch kind {
			case "postgres":
				if strings.HasPrefix(trimmed, `\`) {
					if pgRestrictLine.MatchString(trimmed) {
						continue // pg_dump's own \restrict / \unrestrict lines
					}
					if pgConnectLine.MatchString(trimmed) {
						return Verdict{}, switchesDatabase(line, trimmed)
					}
					return Verdict{}, unsafeLine(line, trimmed)
				}
			case "mysql":
				// the client knows its named commands only in an empty statement
				if mysqlLongCmd.MatchString(trimmed) {
					return Verdict{}, unsafeLine(line, trimmed)
				}
				if d, ok := ParseDelimiter(trimmed); ok {
					if strings.Contains(trimmed, `\`) {
						return Verdict{}, unsafeLine(line, trimmed)
					}
					if d == "" {
						return Verdict{}, unsureLine(line, trimmed, "a DELIMITER line needs one delimiter and nothing after it")
					}
					l.Delim = d
					continue
				}
			}
		}
		for pos := 0; pos < len(text); {
			if l.Idle() && l.Empty() {
				stmtLine = line
			}
			end, cmd := l.Next(text, pos)
			if cmd >= 0 {
				if kind == "mysql" && strings.HasPrefix(text[cmd:], `\-`) {
					stmt.WriteString(text[pos : cmd+2])
					pos = cmd + 2 // MariaDB's "enable the sandbox mode" line
					continue
				}
				return Verdict{}, unsafeLine(line, trimmed)
			}
			if end < 0 {
				stmt.WriteString(text[pos:])
				break
			}
			if kind == "mysql" {
				stmt.WriteString(text[pos : end-len(l.Delim)])
			} else {
				stmt.WriteString(text[pos:end])
			}
			if err := chk.statement(stmt.String(), stmtLine); err != nil {
				return Verdict{}, err
			}
			stmt.Reset()
			if kind == "postgres" && IsCopyStdin(l.Last()) {
				if strings.TrimSpace(text[end:]) != "" {
					return Verdict{}, unsureLine(line, trimmed, "text follows COPY ... FROM stdin on its line")
				}
				inCopy, copyLine = true, line
				break
			}
			pos = end
		}
		stmt.WriteByte('\n')
		l.EndLine()
	}
	if err := sc.Err(); err != nil {
		return Verdict{}, out.Errf(out.ExitUsage, "BAD_FILE", "the file is not readable text SQL", "cannot read backup: %v", err)
	}
	if inCopy {
		return Verdict{}, unsureLine(copyLine, "COPY ... FROM stdin", `its data has no \. end line`)
	}
	if !l.Idle() {
		return Verdict{}, unsureLine(line, "end of file", "the file ends inside a quote, dollar quote or comment")
	}
	if !l.Empty() { // the last statement has no ; but is run too
		if err := chk.statement(stmt.String(), stmtLine); err != nil {
			return Verdict{}, err
		}
	}
	return chk.verdict(), nil
}

// restoreCheck reads each statement of a restore with the classifier of
// `komando db query` (splitSQL): it collects the rules a restore names and
// refuses changes to the settings that decide how quotes are read.
type restoreCheck struct {
	kind  string
	d     dialect
	saved map[string]bool // mysql: user variables that hold the session's own sql_mode (@OLD_SQL_MODE)
	first map[string]int  // rule ID: the line where it first appears
	more  map[string]int  // rule ID: how many more statements match it
	order []string
}

func newRestoreCheck(kind string) *restoreCheck {
	d := dialects[kind]
	d.execAsCode = true // mysqldump writes /*!40101 ... */ all over; MySQL runs what is inside
	return &restoreCheck{kind: kind, d: d, saved: map[string]bool{}, first: map[string]int{}, more: map[string]int{}}
}

func (c *restoreCheck) flag(id string, line int) {
	if _, ok := c.first[id]; ok {
		c.more[id]++
		return
	}
	c.first[id] = line
	c.order = append(c.order, id)
}

func (c *restoreCheck) verdict() Verdict {
	v := Verdict{}
	for _, id := range c.order {
		why := fmt.Sprintf("%s (line %d)", RuleReason(id), c.first[id])
		if n := c.more[id]; n > 0 {
			why = fmt.Sprintf("%s (line %d and %d more)", RuleReason(id), c.first[id], n)
		}
		v.RuleIDs = append(v.RuleIDs, id)
		v.Reasons = append(v.Reasons, why)
		v.Risk = RiskDestructive
	}
	return v
}

// statement checks one statement of the file; raw is its text as the file
// has it (comments included, without the mysql delimiter), line its first line.
func (c *restoreCheck) statement(raw string, line int) error {
	if len(raw) > maxInspect {
		c.flag("sql-opaque", line)
		return nil
	}
	_, toks, err := splitSQL(raw, c.d)
	if err != nil {
		return unsureLine(line, firstLineOf(raw), "komando's SQL reader and its restore reader disagree about it")
	}
	for _, ts := range toks {
		if err := c.settings(ts, line, raw); err != nil {
			return err
		}
		_, rules, _ := classifyStatement(ts, false)
		for _, id := range rules {
			if restoreRules[id] {
				c.flag(id, line)
			}
		}
	}
	return nil
}

// settings refuses a statement that changes how quotes are read from then
// on: standard_conforming_strings in PostgreSQL (only SET ... = on, which
// pg_dump writes, is fine), NO_BACKSLASH_ESCAPES in MySQL's sql_mode.
func (c *restoreCheck) settings(ts []token, line int, raw string) error {
	first := firstWord(ts)
	name := func(t token) string {
		if t.word == "\x00ident" {
			return t.ident
		}
		return t.word
	}
	for i, t := range ts {
		switch {
		case c.kind == "postgres" && first == "RESET" && (t.word == "STANDARD_CONFORMING_STRINGS" || t.word == "ALL"):
			return unsureLine(line, firstLineOf(raw), "it resets standard_conforming_strings to the server's default")
		case c.kind == "postgres" && first == "SET" && t.word == "STANDARD_CONFORMING_STRINGS":
			if !pgConformingOn(ts, i) {
				return unsureLine(line, firstLineOf(raw), "it changes standard_conforming_strings")
			}
		case c.kind == "postgres" && name(t) == "SET_CONFIG" && i+1 < len(ts) && ts[i+1].punct == '(':
			if !(i+3 < len(ts) && ts[i+2].punct == '\'' && ts[i+3].punct == ',') {
				return unsureLine(line, firstLineOf(raw), "set_config with a setting name komando cannot see")
			}
			if strings.EqualFold(strings.TrimSpace(ts[i+2].str), "standard_conforming_strings") {
				return unsureLine(line, firstLineOf(raw), "it changes standard_conforming_strings")
			}
		case c.kind == "mysql" && t.word == "SQL_MODE" && !userVar(ts, i) && setBefore(ts, i):
			v, ok := assigned(ts, i)
			if !ok {
				continue // SET @OLD_SQL_MODE=@@SQL_MODE reads it
			}
			switch {
			case len(v) == 1 && (v[0].punct == '\'' || v[0].word == "\x00ident"):
				text := v[0].str
				if v[0].punct == 0 {
					text = v[0].ident
				}
				if strings.Contains(strings.ToUpper(text), "NO_BACKSLASH_ESCAPES") {
					return unsureLine(line, firstLineOf(raw), "it sets NO_BACKSLASH_ESCAPES")
				}
			case len(v) == 2 && v[0].punct == '@' && v[1].word != "" && c.saved[v[1].word]:
				// back to the mode saved before (mysqldump's SET SQL_MODE=@OLD_SQL_MODE)
			default:
				return unsureLine(line, firstLineOf(raw), "it sets sql_mode to a value komando cannot check")
			}
		}
	}
	if c.kind == "mysql" {
		c.userVars(ts)
	}
	return nil
}

// userVars follows the user variables that hold a saved sql_mode: set by
// SET @v = @@sql_mode, and forgotten when anything else names them.
func (c *restoreCheck) userVars(ts []token) {
	for i := range ts {
		if i+1 >= len(ts) || ts[i].punct != '@' || ts[i+1].word == "" || i > 0 && ts[i-1].punct == '@' {
			continue
		}
		v := ts[i+1].word
		val, ok := assigned(ts, i+1)
		switch {
		case ok && setBefore(ts, i) && savesMode(val):
			c.saved[v] = true
		case i >= 2 && ts[i-1].punct == '=' && ts[i-2].word == "SQL_MODE":
			// SET SQL_MODE=@v reads it
		default:
			delete(c.saved, v)
		}
	}
}

// savesMode: the value is @@sql_mode or @@session.sql_mode.
func savesMode(v []token) bool {
	switch {
	case len(v) == 3:
		return v[0].punct == '@' && v[1].punct == '@' && v[2].word == "SQL_MODE"
	case len(v) == 5:
		return v[0].punct == '@' && v[1].punct == '@' && v[2].word == "SESSION" && v[3].punct == '.' && v[4].word == "SQL_MODE"
	}
	return false
}

// userVar: ts[i] is the name of a user variable (@name, not @@name).
func userVar(ts []token, i int) bool {
	return i > 0 && ts[i-1].punct == '@' && !(i > 1 && ts[i-2].punct == '@')
}

// setBefore: a SET at the top level comes before ts[i].
func setBefore(ts []token, i int) bool {
	for _, t := range ts[:i] {
		if t.depth == 0 && t.word == "SET" {
			return true
		}
	}
	return false
}

// assigned returns the value tokens when ts[i] is followed by = or := (up
// to the next top-level comma).
func assigned(ts []token, i int) ([]token, bool) {
	j := i + 1
	switch {
	case j < len(ts) && ts[j].punct == '=':
		j++
	case j+1 < len(ts) && ts[j].punct == ':' && ts[j+1].punct == '=':
		j += 2
	default:
		return nil, false
	}
	k := j
	for k < len(ts) && !(ts[k].punct == ',' && ts[k].depth == ts[i].depth) {
		k++
	}
	return ts[j:k], true
}

// pgConformingOn: SET [SESSION|LOCAL] standard_conforming_strings = on
// (or TO on, 'on', true), with ts[i] the setting's name.
func pgConformingOn(ts []token, i int) bool {
	if i+3 != len(ts) || ts[i+1].punct != '=' && ts[i+1].word != "TO" {
		return false
	}
	v := ts[i+2]
	val := v.word
	if v.punct == '\'' {
		val = strings.ToUpper(strings.TrimSpace(v.str))
	}
	return val == "ON" || val == "TRUE"
}

func firstLineOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.IndexByte(raw, '\n'); i >= 0 {
		return raw[:i]
	}
	return raw
}

func short(text string) string {
	if len(text) > 60 {
		return text[:57] + "..."
	}
	return text
}

func unsafeLine(line int, text string) error {
	return out.Errf(out.ExitPolicy, "UNSAFE_BACKUP",
		"the file contains a client command that could run programs or read files where the restore runs; remove that line if the file is not from a trusted dump",
		"line %d is a client command, not SQL: %s", line, short(text))
}

func unsureLine(line int, text, why string) error {
	return out.Errf(out.ExitPolicy, "UNSAFE_BACKUP",
		"komando refuses a backup it cannot read with certainty, because a misread file could hide client commands; restore a file written by `komando db dump`, pg_dump or mysqldump, or fix that line",
		"line %d cannot be checked (%s): %s", line, why, short(text))
}

func switchesDatabase(line int, text string) error {
	return out.Errf(out.ExitUsage, "RESTORE_UNSUPPORTED",
		"the file switches databases (pg_dump --create or pg_dumpall); dump the one database without --create and restore that into this conn",
		"line %d switches to another database: %s", line, short(text))
}

// Lexer follows a SQL file the way psql (kind "postgres") or the mysql
// client (kind "mysql") reads it: quotes, E-strings, dollar quotes,
// comments (nested in PostgreSQL), and where a statement ends (outside
// parentheses and, in PostgreSQL, outside BEGIN ATOMIC ... END bodies).
// CheckRestore and komando's own restore use the same Lexer, so the file
// that was checked is the file that is run.
type Lexer struct {
	Delim string // mysql: the current DELIMITER

	pg      bool
	quote   byte   // open ', " or ` (0 = none)
	esc     bool   // backslash escapes in the open quote
	dollar  string // open $tag$
	comment int    // depth of /* */
	paren   int
	begin   int     // psql: depth of BEGIN ... END in CREATE FUNCTION/PROCEDURE
	idents  [4]byte // psql: the first words of the statement (c, o, r, f, p)
	nIdent  int
	code    strings.Builder // the statement without comments; quoted text left out
	last    string
}

// NewLexer starts a Lexer for kind (postgres or mysql).
func NewLexer(kind string) *Lexer { return &Lexer{Delim: ";", pg: kind == "postgres"} }

// Idle reports whether the lexer is outside quotes, dollar quotes and comments.
func (l *Lexer) Idle() bool { return l.quote == 0 && l.dollar == "" && l.comment == 0 }

// Empty reports whether the current statement has no code yet (only white
// space and comments).
func (l *Lexer) Empty() bool { return l.code.Len() == 0 }

// Last is the code of the statement that ended last: upper-cased words and
// punctuation, comments removed, quoted text shown as a pair of its quote marks.
func (l *Lexer) Last() string { return l.last }

// EndLine tells the lexer a line ended (inside a statement, a line break
// separates words).
func (l *Lexer) EndLine() {
	if l.Idle() {
		l.space()
	}
}

func (l *Lexer) space() {
	if b := l.code.String(); b != "" && b[len(b)-1] != ' ' {
		l.code.WriteByte(' ')
	}
}

// Next reads line from byte i. It returns the position just after the
// delimiter that ends the current statement (then Last is that
// statement), or -1 when the line ends first; and the position of a client
// command (a backslash outside quotes and comments), or -1. It stops at
// whichever comes first. Call EndLine after the last Next of a line.
func (l *Lexer) Next(line string, i int) (end, cmd int) {
	n := len(line)
	for ; i < n; i++ {
		c := line[i]
		switch {
		case l.comment > 0:
			if c == '*' && i+1 < n && line[i+1] == '/' {
				l.comment--
				i++
			} else if l.pg && c == '/' && i+1 < n && line[i+1] == '*' {
				l.comment++
				i++
			}
		case l.dollar != "":
			if strings.HasPrefix(line[i:], l.dollar) {
				i += len(l.dollar) - 1
				l.dollar = ""
			}
		case l.quote != 0:
			if c == '\\' && l.esc {
				i++
			} else if c == l.quote {
				if i+1 < n && line[i+1] == c {
					i++
				} else {
					l.quote = 0
				}
			}
		case c == '\\':
			if !l.pg && i+1 < n && line[i+1] == 'N' { // mysql: \N is NULL
				l.code.WriteString(`\N`)
				i++
				continue
			}
			return -1, i
		case !l.pg && strings.HasPrefix(line[i:], l.Delim):
			l.finish()
			return i + len(l.Delim), -1
		case c == '-' && i+1 < n && line[i+1] == '-' && (l.pg || i+2 >= n || line[i+2] <= ' '), c == '#' && !l.pg:
			return -1, -1 // a comment to the end of the line
		case c == '/' && i+1 < n && line[i+1] == '*' && (l.pg || !strings.HasPrefix(line[i+2:], "!") && !strings.HasPrefix(line[i+2:], "M!")):
			// MySQL runs what is inside /*! ... */: the client reads it as code
			l.comment = 1
			i++
		case c == '\'' || c == '"' || c == '`' && !l.pg:
			// mysql: a backslash escapes in '' and "", never in `names`
			l.quote, l.esc = c, !l.pg && c != '`'
			l.code.WriteString(string([]byte{c, c}))
		case c == '$' && l.pg:
			if tag := pgDollarTag(line[i:]); tag != "" {
				l.dollar = tag
				l.code.WriteString("''")
				i += len(tag) - 1
				continue
			}
			j := i + 1 // $1, a parameter
			for j < n && line[j] >= '0' && line[j] <= '9' {
				j++
			}
			l.code.WriteString(line[i:j])
			i = j - 1
		case c == ';' && l.pg:
			if l.paren == 0 && l.begin == 0 {
				l.finish()
				return i + 1, -1
			}
			l.code.WriteByte(c)
		case c == '(':
			l.paren++
			l.code.WriteByte(c)
		case c == ')':
			if l.paren > 0 {
				l.paren--
			}
			l.code.WriteByte(c)
		case isWord(c):
			j := i + 1
			if c >= '0' && c <= '9' { // a number (never with $)
				for j < n && isWord(line[j]) {
					j++
				}
			} else { // an identifier or keyword; psql lets $ continue it
				for j < n && (isWord(line[j]) || l.pg && line[j] == '$') {
					j++
				}
			}
			word := line[i:j]
			if l.pg && (word == "E" || word == "e") && j < n && line[j] == '\'' {
				l.quote, l.esc = '\'', true // E'...': backslash escapes
				l.code.WriteString("''")
				i = j
				continue
			}
			if l.pg && !(c >= '0' && c <= '9') {
				l.trackBegin(word)
			}
			l.code.WriteString(strings.ToUpper(word))
			i = j - 1
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			l.space()
		default:
			l.code.WriteByte(c)
		}
	}
	return -1, -1
}

// pgDollarTag returns psql's $tag$ at the start of s, or "": a letter, _
// or any byte of a non-ASCII character first, then those or digits.
func pgDollarTag(s string) string {
	letter := func(c byte) bool { return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80 }
	j := 1
	if j < len(s) && letter(s[j]) {
		for j++; j < len(s) && (letter(s[j]) || s[j] >= '0' && s[j] <= '9'); j++ {
		}
	}
	if j < len(s) && s[j] == '$' {
		return s[:j+1]
	}
	return ""
}

// trackBegin is psql's rule for SQL-standard function bodies: in CREATE
// [OR REPLACE] FUNCTION/PROCEDURE, outside parentheses, BEGIN (and CASE
// inside it) opens a block that END closes, and a ; inside does not end
// the statement.
func (l *Lexer) trackBegin(word string) {
	w := strings.ToLower(word)
	if l.nIdent < len(l.idents) {
		switch w {
		case "create", "function", "procedure", "or", "replace":
			l.idents[l.nIdent] = w[0]
		}
	}
	l.nIdent++
	id := l.idents
	if id[0] != 'c' || l.paren != 0 || !(id[1] == 'f' || id[1] == 'p' || id[1] == 'o' && id[2] == 'r' && (id[3] == 'f' || id[3] == 'p')) {
		return
	}
	switch w {
	case "begin":
		l.begin++
	case "case":
		if l.begin >= 1 {
			l.begin++
		}
	case "end":
		if l.begin > 0 {
			l.begin--
		}
	}
}

// Reset forgets the statement in progress (the scanner calls it at the end
// of the file, after it returned the last statement).
func (l *Lexer) Reset() {
	l.code.Reset()
	l.quote, l.esc, l.dollar, l.comment = 0, false, "", 0
	l.paren, l.begin, l.nIdent, l.idents = 0, 0, 0, [4]byte{}
}

func (l *Lexer) finish() {
	l.last = strings.TrimSpace(l.code.String())
	l.code.Reset()
	l.paren, l.begin, l.nIdent, l.idents = 0, 0, 0, [4]byte{}
}
