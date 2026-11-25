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
// N, U&) and quotes. PASSWORD = 0x... HASHED is a password=value, which
// maskAssign (output) and redactSQL's connection-string pass (audit) hide.
var sqlPassword = regexp.MustCompile(`(?is)(\bPASSWORD(?:` + SQLGap + `FOR` + SQLGap + `\S+?` + sqlGap0 + `=)?` + sqlGap0 + `(?:[=(]` + sqlGap0 + `)*|` +
	`\bIDENTIFIED` + SQLGap + `(?:WITH` + SQLGap + `\S+` + SQLGap + `)?BY` + SQLGap + `(?:VALUES` + SQLGap + `)?)` +
	`((?:[EN]|U&)?(?:'(?:[^'\\]|''|\\.)*'|"(?:[^"\\]|""|\\.)*"|\$[A-Za-z_]*\$.*?\$[A-Za-z_]*\$))`)

// sqlBarePassword is Oracle's IDENTIFIED BY password without quotes.
// Group 3 is a quote or & right after the word: then the word is a
// literal's prefix (E'...', U&'...'), which sqlPassword covers.
var sqlBarePassword = regexp.MustCompile(`(?is)(\bIDENTIFIED` + SQLGap + `BY` + SQLGap + `)([^\s;,)'"$][^\s;,)'"&]*)([&'"]?)`)

// sqlOldPassword is the old password in Oracle's ALTER USER u IDENTIFIED
// BY new REPLACE old, quoted or not, once the new one is hidden.
var sqlOldPassword = regexp.MustCompile(`(?is)(\bIDENTIFIED` + SQLGap + `BY` + SQLGap + `(?:'[^']*'|"[^"]*"|\S+)` + SQLGap + `REPLACE` + SQLGap + `)('(?:[^']|'')*'|"(?:[^"]|"")*"|[^\s;,)'"]+)()`)

// SQLPasswords replaces each password in SQL text with repl(literal); the
// literal is passed as written: prefix and quotes included, or Oracle's
// bare word. A quoted key ("password": "x", 'password':
// 'x') is no SQL and is left to the other maskers.
func SQLPasswords(s string, repl func(lit string) string) string {
	s = replaceSQL(s, sqlPassword, repl, func(head, lit string, at int) bool {
		return len(head) == len("PASSWORD") && at > 0 && s[at-1] == lit[0]
	})
	hidden := func(lit string) bool {
		return lit == Hidden || lit == "***" || strings.Trim(lit, `'"`) == Hidden || strings.Trim(lit, `'"`) == "***"
	}
	s = replaceSQL(s, sqlBarePassword, repl, func(_, lit string, _ int) bool {
		return hidden(lit) || strings.EqualFold(lit, "VALUES") || strings.EqualFold(lit, "PASSWORD")
	})
	return replaceSQL(s, sqlOldPassword, repl, func(_, lit string, _ int) bool { return hidden(lit) })
}

// replaceSQL replaces group 2 of each match of re with repl(group 2),
// unless skip says so or group 3 is not empty.
func replaceSQL(s string, re *regexp.Regexp, repl func(string) string, skip func(head, lit string, at int) bool) string {
	idx := re.FindAllStringSubmatchIndex(s, -1)
	if idx == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range idx {
		head, lit := s[m[2]:m[3]], s[m[4]:m[5]]
		if len(m) > 7 && m[6] >= 0 && m[7] > m[6] || skip(head, lit, m[2]) {
			continue
		}
		b.WriteString(s[last:m[4]])
		b.WriteString(repl(lit))
		last = m[5]
	}
	b.WriteString(s[last:])
	return b.String()
}

// SQLQuoted splits a quoted literal into its prefix (E, N, U&) and the
// rest; ok is false for a bare word.
func SQLQuoted(lit string) (prefix string, ok bool) {
	body := strings.TrimLeft(lit, "EeNnUu&")
	if len(lit)-len(body) > 2 || body == "" || !strings.ContainsRune(`'"$`, rune(body[0])) {
		return "", false
	}
	return lit[:len(lit)-len(body)], true
}

// hideSQLPassword keeps a literal's prefix and quotes and hides its text:
// 'x' is '[hidden]', $$x$$ is $$[hidden]$$, a bare word is [hidden].
func hideSQLPassword(lit string) string {
	prefix, ok := SQLQuoted(lit)
	if !ok {
		return Hidden
	}
	body := lit[len(prefix):]
	if body[0] == '$' {
		tag := body[:strings.Index(body[1:], "$")+2]
		return prefix + tag + Hidden + tag
	}
	return prefix + body[:1] + Hidden + body[:1]
}

// sqlHiddenNext reports whether s at i starts a literal the SQL pass hid,
// so PASSWORD = N'[hidden]' keeps its N.
func sqlHiddenNext(s string, i int) bool {
	rest := s[i:]
	return strings.HasPrefix(rest, "'"+Hidden+"'") || strings.HasPrefix(rest, `"`+Hidden+`"`)
}
