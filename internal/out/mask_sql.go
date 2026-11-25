package out

import (
	"regexp"
	"strings"
)

// SQLGap is the space between two SQL words, which may hold comments
// (IDENTIFIED/**/BY).
const SQLGap = `(?:\s|/\*.*?\*/|--[^\n]*\n)+`

const sqlGap0 = `(?:\s|/\*.*?\*/|--[^\n]*\n)*`

// sqlPassword matches the password literal in CREATE/ALTER USER and ROLE,
// SET PASSWORD and PASSWORD(): PASSWORD 'x' and ENCRYPTED PASSWORD 'x'
// (Postgres), IDENTIFIED [WITH plugin] BY 'x', SET PASSWORD [FOR u] = 'x'
// (MySQL), PASSWORD = N'x' (SQL Server), IDENTIFIED BY VALUES 'hash'
// (Oracle). Group 1 is the head, group 2 the literal with its prefix (E,
// N, U&) and quotes.
var sqlPassword = regexp.MustCompile(`(?is)(\bPASSWORD(?:` + SQLGap + `FOR` + SQLGap + `\S+?` + sqlGap0 + `=)?` + sqlGap0 + `(?:[=(]` + sqlGap0 + `)*|` +
	`\bIDENTIFIED` + SQLGap + `(?:WITH` + SQLGap + `\S+` + SQLGap + `)?BY` + SQLGap + `(?:VALUES` + SQLGap + `)?)` +
	`((?:[EN]|U&)?(?:'(?:[^'\\]|''|\\.)*'|"(?:[^"\\]|""|\\.)*"|\$[A-Za-z_]*\$.*?\$[A-Za-z_]*\$))`)

// SQLPasswords replaces each password literal in SQL text with
// repl(literal); the literal is passed as written, prefix and quotes
// included. A quoted key ("password": "x", 'password': 'x') is no SQL
// and is left to the other maskers.
func SQLPasswords(s string, repl func(lit string) string) string {
	idx := sqlPassword.FindAllStringSubmatchIndex(s, -1)
	if idx == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range idx {
		head, lit := s[m[2]:m[3]], s[m[4]:m[5]]
		if len(head) == len("PASSWORD") && m[2] > 0 && s[m[2]-1] == lit[0] {
			continue
		}
		b.WriteString(s[last:m[4]])
		b.WriteString(repl(lit))
		last = m[5]
	}
	b.WriteString(s[last:])
	return b.String()
}

// SQLLiteralPrefix is a literal's prefix (E, N, U&), "" when it has none.
func SQLLiteralPrefix(lit string) string {
	return lit[:len(lit)-len(strings.TrimLeft(lit, "EeNnUu&"))]
}

// hideSQLPassword keeps a literal's prefix and quotes and hides its text:
// 'x' is '[hidden]', $$x$$ is $$[hidden]$$.
func hideSQLPassword(lit string) string {
	body := lit[len(SQLLiteralPrefix(lit)):]
	if strings.HasPrefix(body, "$") {
		tag := body[:strings.Index(body[1:], "$")+2]
		return lit[:len(lit)-len(body)] + tag + Hidden + tag
	}
	q := body[:1]
	return lit[:len(lit)-len(body)] + q + Hidden + q
}

// sqlHiddenNext reports whether s at i starts a literal the SQL pass hid,
// so PASSWORD = N'[hidden]' keeps its N.
func sqlHiddenNext(s string, i int) bool {
	rest := s[i:]
	return strings.HasPrefix(rest, "'"+Hidden+"'") || strings.HasPrefix(rest, `"`+Hidden+`"`)
}
