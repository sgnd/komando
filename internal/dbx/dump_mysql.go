package dbx

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

// DumpOptions narrow a built-in dump.
type DumpOptions struct {
	SchemaOnly bool
	Tables     []string
}

// Dump writes a plain SQL backup of the database, made by komando itself
// (no pg_dump or mysqldump). It reads inside one consistent snapshot.
// Objects it cannot write faithfully stop it with their names, so a dump
// never silently misses something.
func Dump(ctx context.Context, db *sql.DB, kind string, o DumpOptions, w io.Writer) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	var err error
	switch kind {
	case "mysql":
		err = dumpMySQL(ctx, db, o, bw)
	case "postgres":
		err = dumpPostgres(ctx, db, o, bw)
	default:
		return fmt.Errorf("%s has no SQL dump", kind)
	}
	if err != nil {
		return err
	}
	return bw.Flush()
}

func qid(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

func dumpMySQL(ctx context.Context, db *sql.DB, o DumpOptions, w *bufio.Writer) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, q := range []string{"SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ", "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return mysqlErr(err)
		}
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
	var dbName string
	if err := conn.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&dbName); err != nil {
		return mysqlErr(err)
	}
	fmt.Fprintf(w, "-- komando dump of MySQL database %s, %s\n", dbName, time.Now().UTC().Format(time.RFC3339))
	w.WriteString("SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\nSET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n\n")

	type obj struct{ name, typ string }
	var tables []obj
	rows, err := conn.QueryContext(ctx, "SHOW FULL TABLES")
	if err != nil {
		return mysqlErr(err)
	}
	for rows.Next() {
		var o obj
		if err := rows.Scan(&o.name, &o.typ); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, o)
	}
	rows.Close()
	want := map[string]bool{}
	for _, t := range o.Tables {
		want[t] = true
	}
	seen := map[string]bool{}
	for _, t := range tables {
		seen[t.name] = true
	}
	for _, t := range o.Tables {
		if !seen[t] {
			return fmt.Errorf("no table %q in %s", t, dbName)
		}
	}
	// tables first, then views (they may select from each other's tables)
	for _, pass := range []string{"BASE TABLE", "VIEW"} {
		for _, t := range tables {
			if t.typ != pass || len(want) > 0 && !want[t.name] {
				continue
			}
			if pass == "VIEW" {
				var name, create string
				var cs, coll sql.NullString
				if err := conn.QueryRowContext(ctx, "SHOW CREATE VIEW "+qid(t.name)).Scan(&name, &create, &cs, &coll); err != nil {
					return mysqlErr(err)
				}
				fmt.Fprintf(w, "DROP VIEW IF EXISTS %s;\n%s;\n\n", qid(t.name), stripDefiner(create))
				continue
			}
			var name, create string
			if err := conn.QueryRowContext(ctx, "SHOW CREATE TABLE "+qid(t.name)).Scan(&name, &create); err != nil {
				return mysqlErr(err)
			}
			fmt.Fprintf(w, "DROP TABLE IF EXISTS %s;\n%s;\n\n", qid(t.name), create)
			if !o.SchemaOnly {
				if err := mysqlRows(ctx, conn, t.name, w); err != nil {
					return err
				}
			}
		}
	}
	if len(want) == 0 { // triggers and routines belong to the whole database
		if err := mysqlRoutines(ctx, conn, dbName, w); err != nil {
			return err
		}
	}
	w.WriteString("SET FOREIGN_KEY_CHECKS=1;\nSET UNIQUE_CHECKS=1;\n")
	return nil
}

// mysqlRows writes the table's rows as INSERT statements of about 1 MB.
func mysqlRows(ctx context.Context, conn *sql.Conn, table string, w *bufio.Writer) error {
	rows, err := conn.QueryContext(ctx, "SELECT * FROM "+qid(table))
	if err != nil {
		return mysqlErr(err)
	}
	defer rows.Close()
	cols, err := rows.ColumnTypes()
	if err != nil {
		return err
	}
	names := make([]string, len(cols))
	binary := make([]bool, len(cols))
	for i, c := range cols {
		names[i] = qid(c.Name())
		t := strings.ToUpper(c.DatabaseTypeName())
		binary[i] = strings.Contains(t, "BLOB") || strings.Contains(t, "BINARY") || t == "BIT" || t == "GEOMETRY"
	}
	head := "INSERT INTO " + qid(table) + " (" + strings.Join(names, ",") + ") VALUES\n"
	vals := make([]sql.RawBytes, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	size := 0
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		if size == 0 {
			w.WriteString(head)
		} else {
			w.WriteString(",\n")
		}
		var b strings.Builder
		b.WriteString("(")
		for i, v := range vals {
			if i > 0 {
				b.WriteString(",")
			}
			switch {
			case v == nil:
				b.WriteString("NULL")
			case binary[i]:
				if len(v) == 0 {
					b.WriteString("''")
				} else {
					b.WriteString("0x" + hex.EncodeToString(v))
				}
			default:
				b.WriteString(mysqlQuote(string(v)))
			}
		}
		b.WriteString(")")
		w.WriteString(b.String())
		size += b.Len()
		if size > 1<<20 {
			w.WriteString(";\n")
			size = 0
		}
	}
	if size > 0 {
		w.WriteString(";\n")
	}
	w.WriteString("\n")
	return rows.Err()
}

// mysqlQuote quotes a value as a MySQL string literal. Numbers are quoted
// too; MySQL converts them back exactly.
func mysqlQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case 0:
			b.WriteString(`\0`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		case 0x1a:
			b.WriteString(`\Z`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// mysqlRoutines writes triggers, procedures and functions between
// DELIMITER lines, as mysqldump does (komando's restore reads them too).
func mysqlRoutines(ctx context.Context, conn *sql.Conn, dbName string, w *bufio.Writer) error {
	var bodies []string
	rows, err := conn.QueryContext(ctx, "SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ? ORDER BY ACTION_ORDER, TRIGGER_NAME", dbName)
	if err != nil {
		return mysqlErr(err)
	}
	var trigs []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		trigs = append(trigs, n)
	}
	rows.Close()
	for _, t := range trigs {
		r, err := conn.QueryContext(ctx, "SHOW CREATE TRIGGER "+qid(t))
		if err != nil {
			return mysqlErr(err)
		}
		cols, _ := r.Columns()
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if r.Next() {
			r.Scan(ptrs...)
			bodies = append(bodies, "DROP TRIGGER IF EXISTS "+qid(t)+";;\n"+stripDefiner(vals[2].String)+";;")
		}
		r.Close()
	}
	for _, kind := range []string{"PROCEDURE", "FUNCTION"} {
		rows, err := conn.QueryContext(ctx, "SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ? AND ROUTINE_TYPE = ? ORDER BY 1", dbName, kind)
		if err != nil {
			return mysqlErr(err)
		}
		var names []string
		for rows.Next() {
			var n string
			rows.Scan(&n)
			names = append(names, n)
		}
		rows.Close()
		for _, n := range names {
			r, err := conn.QueryContext(ctx, "SHOW CREATE "+kind+" "+qid(n))
			if err != nil {
				return mysqlErr(err)
			}
			cols, _ := r.Columns()
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if r.Next() {
				r.Scan(ptrs...)
				bodies = append(bodies, "DROP "+kind+" IF EXISTS "+qid(n)+";;\n"+stripDefiner(vals[2].String)+";;")
			}
			r.Close()
		}
	}
	if len(bodies) == 0 {
		return nil
	}
	w.WriteString("DELIMITER ;;\n")
	for _, b := range bodies {
		w.WriteString(b + "\n")
	}
	w.WriteString("DELIMITER ;\n\n")
	return nil
}

// stripDefiner drops DEFINER=`user`@`host`: the account may not exist
// where the dump is restored, and restoring it would need SUPER.
func stripDefiner(s string) string {
	i := strings.Index(s, "DEFINER=")
	if i < 0 {
		return s
	}
	j := i + len("DEFINER=")
	// `user`@`host` or user@host, ends at the next space
	for j < len(s) && s[j] != ' ' {
		if s[j] == '`' {
			k := strings.IndexByte(s[j+1:], '`')
			if k < 0 {
				break
			}
			j += k + 2
			continue
		}
		j++
	}
	return strings.TrimSpace(s[:i]) + " " + strings.TrimSpace(s[j:])
}
