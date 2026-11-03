package dbx

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/stdlib"
)

// Restore runs a plain SQL backup (komando's own, pg_dump's or
// mysqldump's) without psql or mysql. PostgreSQL restores in one
// transaction and stops at the first error, like psql
// --single-transaction -v ON_ERROR_STOP=1; COPY ... FROM stdin blocks are
// streamed. MySQL runs the statements in order and understands DELIMITER.
// The file must have passed driver.CheckRestore.
func Restore(ctx context.Context, db *sql.DB, kind string, r io.Reader) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	sc := newSQLScanner(r, kind)
	if kind == "postgres" {
		if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
			return err
		}
		done := false
		defer func() {
			if !done {
				conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
			}
		}()
		for {
			st, err := sc.next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if pgCopyFrom.MatchString(st.text) {
				if err := copyFrom(ctx, conn, st.text, sc); err != nil {
					return fmt.Errorf("line %d: %w", st.line, err)
				}
				continue
			}
			if _, err := conn.ExecContext(ctx, st.text); err != nil {
				return fmt.Errorf("line %d: %w", st.line, err)
			}
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return err
		}
		done = true
		return nil
	}
	for {
		st, err := sc.next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, st.text); err != nil {
			return fmt.Errorf("line %d: %w", st.line, mysqlErr(err))
		}
	}
}

var pgCopyFrom = regexp.MustCompile(`(?is)^COPY\s+.+\s+FROM\s+stdin`)

// copyFrom streams the data lines after a COPY statement up to "\.".
func copyFrom(ctx context.Context, conn *sql.Conn, stmt string, sc *sqlScanner) error {
	pr, pw := io.Pipe()
	go func() {
		for {
			line, err := sc.rawLine()
			if err != nil {
				pw.CloseWithError(fmt.Errorf("the COPY data has no \\. end"))
				return
			}
			if line == `\.` {
				pw.Close()
				return
			}
			if _, err := io.WriteString(pw, line+"\n"); err != nil {
				return
			}
		}
	}()
	q := strings.TrimSuffix(strings.TrimSpace(stmt), ";")
	q = regexp.MustCompile(`(?i)FROM\s+stdin`).ReplaceAllString(q, "FROM STDIN")
	err := conn.Raw(func(dc any) error {
		c, ok := dc.(*stdlib.Conn)
		if !ok {
			return fmt.Errorf("not a PostgreSQL connection")
		}
		_, err := c.Conn().PgConn().CopyFrom(ctx, pr, q)
		return err
	})
	pr.Close()
	return err
}

type sqlStatement struct {
	text string
	line int
}

// sqlScanner splits a SQL file into statements at ; (or the current
// DELIMITER), outside quotes, dollar quotes and comments. psql's \restrict
// and \unrestrict lines are skipped; driver.CheckRestore refuses others.
type sqlScanner struct {
	rd      *bufio.Reader
	kind    string
	delim   string
	line    int
	pending *string // the rest of a line after a statement's end
}

func newSQLScanner(r io.Reader, kind string) *sqlScanner {
	return &sqlScanner{rd: bufio.NewReaderSize(r, 1<<20), kind: kind, delim: ";", line: 0}
}

func (s *sqlScanner) rawLine() (string, error) {
	if s.pending != nil {
		l := *s.pending
		s.pending = nil
		return l, nil
	}
	l, err := s.rd.ReadString('\n')
	if err != nil && (err != io.EOF || l == "") {
		return "", err
	}
	s.line++
	return strings.TrimRight(l, "\r\n"), nil
}

func (s *sqlScanner) next() (sqlStatement, error) {
	var b strings.Builder
	start := 0
	var quote byte
	dollar := ""
	block := false
	backslash := s.kind == "mysql"
	for {
		line, err := s.rawLine()
		if err != nil {
			if err == io.EOF && strings.TrimSpace(b.String()) != "" {
				return sqlStatement{strings.TrimSpace(b.String()), start}, nil
			}
			return sqlStatement{}, err
		}
		trimmed := strings.TrimSpace(line)
		if b.Len() == 0 && quote == 0 && dollar == "" && !block {
			if trimmed == "" || strings.HasPrefix(trimmed, "--") || s.kind == "mysql" && strings.HasPrefix(trimmed, "#") {
				continue
			}
			if s.kind == "postgres" && (strings.HasPrefix(trimmed, `\restrict`) || strings.HasPrefix(trimmed, `\unrestrict`)) {
				continue
			}
			if s.kind == "mysql" && strings.HasPrefix(strings.ToUpper(trimmed), "DELIMITER ") {
				s.delim = strings.TrimSpace(trimmed[len("DELIMITER "):])
				continue
			}
			start = s.line
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			switch {
			case block:
				if c == '*' && i+1 < len(line) && line[i+1] == '/' {
					block, i = false, i+1
				}
			case dollar != "":
				if strings.HasPrefix(line[i:], dollar) {
					i += len(dollar) - 1
					dollar = ""
				}
			case quote != 0:
				if c == '\\' && backslash && quote != '`' {
					i++
				} else if c == quote {
					quote = 0
				}
			case c == '\'' || c == '"' || c == '`':
				quote = c
			case c == '-' && i+1 < len(line) && line[i+1] == '-', c == '#' && s.kind == "mysql":
				i = len(line)
			case c == '/' && i+1 < len(line) && line[i+1] == '*' && !(i+2 < len(line) && line[i+2] == '!'):
				block, i = true, i+1
			case c == '$' && s.kind == "postgres":
				j := i + 1
				for j < len(line) && (line[j] == '_' || line[j] >= 'a' && line[j] <= 'z' || line[j] >= 'A' && line[j] <= 'Z' || line[j] >= '0' && line[j] <= '9') {
					j++
				}
				if j < len(line) && line[j] == '$' && (j == i+1 || !(line[i+1] >= '0' && line[i+1] <= '9')) {
					dollar = line[i : j+1]
					i = j
				}
			case strings.HasPrefix(line[i:], s.delim):
				b.WriteString(line[:i])
				if s.delim == ";" && s.kind == "postgres" {
					b.WriteString(";")
				}
				if rest := strings.TrimSpace(line[i+len(s.delim):]); rest != "" && !strings.HasPrefix(rest, "--") {
					s.pending = &rest // another statement on the same line
				}
				return sqlStatement{strings.TrimSpace(b.String()), start}, nil
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
}
