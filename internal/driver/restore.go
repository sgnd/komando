package driver

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// psql and the mysql client obey their own commands inside a SQL file
// (`\! rm -rf /`, `system ...`, `\i other.sql`), which run on the machine
// that restores. CheckRestore reads a whole backup before anything is sent
// and refuses client commands other than the ones dumps themselves emit.

var (
	pgAllowedMeta = regexp.MustCompile(`^\\(connect|c|restrict|unrestrict)\b`)
	pgCopyStdin   = regexp.MustCompile(`(?i)^COPY\b.*\bFROM\s+stdin\b.*;\s*$`)
	dollarTag     = regexp.MustCompile(`^\$[A-Za-z_]*\$`)
	mysqlLongCmd  = regexp.MustCompile(`(?i)^\s*(system|source|connect|pager|tee|nopager|notee|edit|charset|warnings)\b`)
)

// CheckRestore returns an error naming the first line with a client command
// that could run code or read files where the restore runs.
func CheckRestore(kind string, r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	d := dialects[kind]
	inCopy := false
	var quote byte    // open ', " or ` (0 = none)
	var dollar string // open $tag$ (postgres)
	block := false    // inside /* */
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if inCopy { // COPY data: backslashes are escapes, the block ends with \.
			if text == `\.` {
				inCopy = false
			}
			continue
		}
		if quote == 0 && dollar == "" && !block {
			trimmed := strings.TrimSpace(text)
			if kind == "mysql" && mysqlLongCmd.MatchString(trimmed) {
				return unsafeLine(line, trimmed)
			}
			if kind == "postgres" && pgCopyStdin.MatchString(trimmed) {
				inCopy = true
				continue
			}
		}
		for i := 0; i < len(text); i++ {
			c := text[i]
			switch {
			case block:
				if c == '*' && i+1 < len(text) && text[i+1] == '/' {
					block = false
					i++
				}
			case dollar != "":
				if strings.HasPrefix(text[i:], dollar) {
					i += len(dollar) - 1
					dollar = ""
				}
			case quote != 0:
				if c == '\\' && d.backslash && quote != '`' {
					i++
				} else if c == quote {
					quote = 0
				}
			case c == '-' && i+1 < len(text) && text[i+1] == '-', c == '#' && kind == "mysql":
				i = len(text)
			case c == '/' && i+1 < len(text) && text[i+1] == '*':
				block = true
				i++
			case c == '\'' || c == '"' || c == '`' && d.backtick:
				quote = c
			case c == '$' && d.dollar:
				if m := dollarTag.FindString(text[i:]); m != "" {
					dollar = m
					i += len(m) - 1
				}
			case c == '\\':
				if kind == "postgres" && pgAllowedMeta.MatchString(text[i:]) && strings.TrimSpace(text[:i]) == "" {
					i = len(text) // pg_dump's own \connect / \restrict lines
					continue
				}
				return unsafeLine(line, strings.TrimSpace(text))
			}
		}
	}
	if err := sc.Err(); err != nil {
		return out.Errf(out.ExitUsage, "BAD_FILE", "the file is not readable text SQL", "cannot read backup: %v", err)
	}
	return nil
}

func unsafeLine(line int, text string) error {
	if len(text) > 60 {
		text = text[:57] + "..."
	}
	return out.Errf(out.ExitPolicy, "UNSAFE_BACKUP",
		"the file contains a client command that could run programs or read files where the restore runs; remove that line if the file is not from a trusted dump",
		"line %d is a client command, not SQL: %s", line, text)
}
