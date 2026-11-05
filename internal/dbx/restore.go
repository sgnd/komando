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

	"github.com/sgnd/komando/internal/driver"
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
			if st.copy {
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
	copy bool // COPY ... FROM stdin: its data lines follow
}

// sqlScanner splits a SQL file into statements at ; (or the current
// DELIMITER) with driver.Lexer, the lexer driver.CheckRestore checks the
// file with: quotes, E-strings, dollar quotes, nested comments and
// BEGIN ATOMIC bodies are followed the way psql and mysql follow them.
// psql's \restrict and \unrestrict lines are skipped; any other client
// command is refused (driver.CheckRestore refuses them first).
type sqlScanner struct {
	rd      *bufio.Reader
	kind    string
	lex     *driver.Lexer
	line    int
	pending *string // the rest of a line after a statement's end
	done    bool    // the file ended
}

func newSQLScanner(r io.Reader, kind string) *sqlScanner {
	return &sqlScanner{rd: bufio.NewReaderSize(r, 1<<20), kind: kind, lex: driver.NewLexer(kind)}
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
	if s.done {
		return sqlStatement{}, io.EOF
	}
	var b strings.Builder
	start := 0
	for {
		line, err := s.rawLine()
		if err != nil {
			if err != io.EOF {
				return sqlStatement{}, err
			}
			// the last statement may have no ; at the end: it runs once
			s.done = true
			text := strings.TrimSpace(b.String())
			empty := s.lex.Empty()
			s.lex.Reset()
			if empty || text == "" {
				return sqlStatement{}, io.EOF
			}
			return sqlStatement{text: text, line: start}, nil
		}
		if b.Len() == 0 && s.lex.Idle() && s.lex.Empty() { // a new statement
			trimmed := strings.TrimSpace(line)
			if s.kind == "postgres" && strings.HasPrefix(trimmed, `\`) {
				if strings.HasPrefix(trimmed, `\restrict`) || strings.HasPrefix(trimmed, `\unrestrict`) {
					continue
				}
				return sqlStatement{}, fmt.Errorf("line %d: %s is a psql command; komando's restore runs SQL only", s.line, trimmed)
			}
			if s.kind == "mysql" {
				if d, ok := driver.ParseDelimiter(trimmed); ok {
					if d == "" {
						return sqlStatement{}, fmt.Errorf("line %d: komando cannot follow this DELIMITER line: %s", s.line, trimmed)
					}
					s.lex.Delim = d
					continue
				}
			}
			start = s.line
		}
		from := 0 // where the statement starts on this line
		for pos := 0; pos < len(line); {
			end, cmd := s.lex.Next(line, pos)
			if cmd >= 0 {
				if s.kind == "mysql" && strings.HasPrefix(line[cmd:], `\-`) {
					pos = cmd + 2 // MariaDB's sandbox line, inside /*M! ... */
					continue
				}
				return sqlStatement{}, fmt.Errorf("line %d: a client command (%s); komando's restore runs SQL only", s.line, strings.TrimSpace(line[cmd:]))
			}
			if end < 0 {
				break
			}
			code := s.lex.Last()
			if code == "" { // only comments before the delimiter
				b.Reset()
				pos, from = end, end
				continue
			}
			text := line[from:end]
			if s.kind == "mysql" {
				text = line[from : end-len(s.lex.Delim)]
			}
			b.WriteString(text)
			if rest := strings.TrimSpace(line[end:]); rest != "" {
				s.pending = &rest // another statement on the same line
			}
			return sqlStatement{text: strings.TrimSpace(b.String()), line: start, copy: s.kind == "postgres" && driver.IsCopyStdin(code)}, nil
		}
		s.lex.EndLine()
		if b.Len() == 0 && s.lex.Idle() && s.lex.Empty() {
			continue // a blank or comment line between statements
		}
		b.WriteString(line[from:])
		b.WriteString("\n")
	}
}
