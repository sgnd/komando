package dbx

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
)

// The PostgreSQL dump writes what pg_dump --no-owner --no-acl writes for the
// common objects: extensions, schemas, enum, domain and composite types,
// functions and procedures, sequences, tables (identity and generated
// columns, partitions, unlogged), data (COPY), constraints, indexes,
// views, materialized views, triggers, row-level security policies and
// comments. Anything else it finds stops the dump with its name.

const pgUserNS = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%'`

func pgExt(alias string) string {
	return "NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = " + alias + ".oid AND d.deptype = 'e')"
}

func pqid(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func pqlit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

type pgTable struct {
	oid              uint32
	schema, name     string
	kind             string // r or p
	unlogged, isPart bool
	parent           string
	bound, partKey   string
	rls, forceRLS    bool
}

func (t pgTable) qname() string { return pqid(t.schema) + "." + pqid(t.name) }

func dumpPostgres(ctx context.Context, db *sql.DB, o DumpOptions, w *bufio.Writer) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"); err != nil {
		return err
	}
	// an empty search path makes the server write every name in full in
	// the definitions it prints (defaults, views, functions), as pg_dump
	// does; the restore runs with the same empty path
	if _, err := conn.ExecContext(ctx, "SET LOCAL search_path = ''"); err != nil {
		return err
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
	q := func(query string, args ...any) ([][]sql.NullString, error) {
		rows, err := conn.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("%w (in %s)", err, firstWords(query))
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		var out [][]sql.NullString
		for rows.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return nil, err
			}
			out = append(out, vals)
		}
		return out, rows.Err()
	}
	whole := len(o.Tables) == 0
	if whole {
		if err := pgUnsupported(q); err != nil {
			return err
		}
	}
	var dbName, version string
	conn.QueryRowContext(ctx, "SELECT current_database(), current_setting('server_version')").Scan(&dbName, &version)
	fmt.Fprintf(w, "-- komando dump of PostgreSQL database %s (server %s), %s\n", dbName, version, time.Now().UTC().Format(time.RFC3339))
	w.WriteString("-- owners and privileges are not included (like pg_dump --no-owner --no-acl)\n\n")
	w.WriteString("SET statement_timeout = 0;\nSET lock_timeout = 0;\nSET client_encoding = 'UTF8';\nSET standard_conforming_strings = on;\n" +
		"SET check_function_bodies = false;\nSET client_min_messages = warning;\nSELECT pg_catalog.set_config('search_path', '', false);\n\n")

	tables, err := pgTables(q, o.Tables)
	if err != nil {
		return err
	}
	if whole {
		if err := pgPreamble(q, w); err != nil {
			return err
		}
	}
	// sequences that are not identity columns' own
	seqs, err := q(`SELECT n.nspname, c.relname, format_type(s.seqtypid, NULL), s.seqstart, s.seqincrement, s.seqmin, s.seqmax, s.seqcache, s.seqcycle,
		(SELECT dn.nspname || '.' || dc.relname || '.' || a.attname FROM pg_depend d JOIN pg_class dc ON dc.oid = d.refobjid
		   JOIN pg_namespace dn ON dn.oid = dc.relnamespace JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
		   WHERE d.objid = c.oid AND d.deptype = 'a' LIMIT 1)
		FROM pg_class c JOIN pg_sequence s ON s.seqrelid = c.oid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'S' AND ` + pgUserNS + ` AND ` + pgExt("c") + `
		AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'i')
		ORDER BY c.oid`)
	if err != nil {
		return err
	}
	keepSeq := func(owner string) bool {
		if whole {
			return true
		}
		for _, t := range tables {
			if strings.HasPrefix(owner, t.schema+"."+t.name+".") {
				return true
			}
		}
		return false
	}
	for _, s := range seqs {
		if !keepSeq(s[9].String) {
			continue
		}
		cycle := "NO CYCLE"
		if s[8].String == "true" {
			cycle = "CYCLE"
		}
		fmt.Fprintf(w, "CREATE SEQUENCE %s.%s AS %s START WITH %s INCREMENT BY %s MINVALUE %s MAXVALUE %s CACHE %s %s;\n",
			pqid(s[0].String), pqid(s[1].String), s[2].String, s[3].String, s[4].String, s[5].String, s[6].String, s[7].String, cycle)
	}
	w.WriteString("\n")

	// tables, parents before their partitions
	for _, t := range tables {
		if err := pgCreateTable(q, t, w); err != nil {
			return err
		}
	}
	for _, s := range seqs {
		if owner := s[9].String; owner != "" && keepSeq(owner) {
			p := strings.Split(owner, ".")
			fmt.Fprintf(w, "ALTER SEQUENCE %s.%s OWNED BY %s.%s.%s;\n", pqid(s[0].String), pqid(s[1].String), pqid(p[0]), pqid(p[1]), pqid(p[2]))
		}
	}
	w.WriteString("\n")

	if !o.SchemaOnly {
		raw, err := rawPg(conn)
		if err != nil {
			return err
		}
		for _, t := range tables {
			if t.kind == "p" {
				continue // the rows are in the partitions
			}
			cols, err := q(`SELECT a.attname FROM pg_attribute a WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = '' ORDER BY a.attnum`, t.oid)
			if err != nil {
				return err
			}
			names := make([]string, len(cols))
			for i, c := range cols {
				names[i] = pqid(c[0].String)
			}
			list := strings.Join(names, ", ")
			fmt.Fprintf(w, "COPY %s (%s) FROM stdin;\n", t.qname(), list)
			if err := raw(ctx, w, fmt.Sprintf("COPY %s (%s) TO STDOUT", t.qname(), list)); err != nil {
				return fmt.Errorf("reading %s: %w", t.qname(), err)
			}
			w.WriteString("\\.\n\n")
		}
		// sequence positions, after the data
		for _, s := range seqs {
			if !keepSeq(s[9].String) {
				continue
			}
			var last sql.NullString
			var called bool
			name := pqid(s[0].String) + "." + pqid(s[1].String)
			if err := conn.QueryRowContext(ctx, "SELECT last_value, is_called FROM "+name).Scan(&last, &called); err != nil {
				return err
			}
			fmt.Fprintf(w, "SELECT pg_catalog.setval(%s, %s, %v);\n", pqlit(name), last.String, called)
		}
		idents, err := q(`SELECT n.nspname, c.relname, a.attname, pg_get_serial_sequence(quote_ident(n.nspname) || '.' || quote_ident(c.relname), a.attname)
			FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE a.attidentity <> '' AND c.relkind IN ('r','p') AND ` + pgUserNS)
		if err != nil {
			return err
		}
		for _, id := range idents {
			if !keepTable(tables, id[0].String, id[1].String) || id[3].String == "" {
				continue
			}
			var last sql.NullString
			var called bool
			if err := conn.QueryRowContext(ctx, "SELECT last_value, is_called FROM "+id[3].String).Scan(&last, &called); err != nil {
				return err
			}
			fmt.Fprintf(w, "SELECT pg_catalog.setval(pg_get_serial_sequence(%s, %s), %s, %v);\n",
				pqlit(pqid(id[0].String)+"."+pqid(id[1].String)), pqlit(id[2].String), last.String, called)
		}
		w.WriteString("\n")
	}

	// constraints: keys and checks first, foreign keys last
	for _, pass := range []string{"'p','u','c','x'", "'f'"} {
		cons, err := q(`SELECT n.nspname, c.relname, con.conname, pg_get_constraintdef(con.oid)
			FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE con.contype IN (` + pass + `) AND con.conislocal AND ` + pgUserNS + ` AND c.relkind IN ('r','p')
			ORDER BY c.oid, con.conname`)
		if err != nil {
			return err
		}
		for _, c := range cons {
			if !keepTable(tables, c[0].String, c[1].String) {
				continue
			}
			only := "ONLY "
			if isPartitioned(tables, c[0].String, c[1].String) {
				only = ""
			}
			fmt.Fprintf(w, "ALTER TABLE %s%s.%s ADD CONSTRAINT %s %s;\n", only, pqid(c[0].String), pqid(c[1].String), pqid(c[2].String), c[3].String)
		}
	}
	w.WriteString("\n")
	idx, err := q(`SELECT n.nspname, t.relname, pg_get_indexdef(i.indexrelid)
		FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE ` + pgUserNS + ` AND t.relkind IN ('r','p','m') AND NOT ic.relispartition
		AND NOT EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conindid = i.indexrelid AND con.contype IN ('p','u','x'))
		ORDER BY ic.oid`)
	if err != nil {
		return err
	}
	var matIdx []string
	for _, x := range idx {
		if keepTable(tables, x[0].String, x[1].String) {
			fmt.Fprintf(w, "%s;\n", x[2].String)
		} else if whole {
			matIdx = append(matIdx, x[2].String) // a materialized view's index, after the view
		}
	}
	w.WriteString("\n")

	if whole {
		views, err := q(`SELECT n.nspname, c.relname, c.relkind, pg_get_viewdef(c.oid)
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('v','m') AND ` + pgUserNS + ` AND ` + pgExt("c") + ` ORDER BY c.oid`)
		if err != nil {
			return err
		}
		var mats []string
		for _, v := range views {
			name := pqid(v[0].String) + "." + pqid(v[1].String)
			def := strings.TrimSuffix(strings.TrimSpace(v[3].String), ";")
			if v[2].String == "m" {
				fmt.Fprintf(w, "CREATE MATERIALIZED VIEW %s AS\n%s\nWITH NO DATA;\n\n", name, def)
				mats = append(mats, name)
				continue
			}
			fmt.Fprintf(w, "CREATE VIEW %s AS\n%s;\n\n", name, def)
		}
		late, err := pgFunctions(q, true)
		if err != nil {
			return err
		}
		for _, f := range late {
			fmt.Fprintf(w, "%s;\n\n", f)
		}
		for _, x := range matIdx {
			fmt.Fprintf(w, "%s;\n", x)
		}
		if !o.SchemaOnly {
			for _, m := range mats {
				fmt.Fprintf(w, "REFRESH MATERIALIZED VIEW %s;\n", m)
			}
		}
		w.WriteString("\n")
	}

	trig, err := q(`SELECT n.nspname, c.relname, pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE NOT t.tgisinternal AND ` + pgUserNS + `
		AND NOT EXISTS (SELECT 1 FROM pg_trigger p WHERE p.oid = t.tgparentid) ORDER BY t.oid`)
	if err != nil {
		return err
	}
	for _, t := range trig {
		if whole || keepTable(tables, t[0].String, t[1].String) {
			fmt.Fprintf(w, "%s;\n", t[2].String)
		}
	}
	for _, t := range tables {
		if t.rls {
			fmt.Fprintf(w, "ALTER TABLE %s ENABLE ROW LEVEL SECURITY;\n", t.qname())
		}
		if t.forceRLS {
			fmt.Fprintf(w, "ALTER TABLE %s FORCE ROW LEVEL SECURITY;\n", t.qname())
		}
	}
	pols, err := q(`SELECT schemaname, tablename, policyname, permissive, cmd, array_to_string(roles, ','), qual, with_check FROM pg_policies`)
	if err != nil {
		return err
	}
	for _, p := range pols {
		if !keepTable(tables, p[0].String, p[1].String) {
			continue
		}
		var roles []string
		for _, r := range strings.Split(p[5].String, ",") {
			if r == "public" {
				roles = append(roles, "PUBLIC")
			} else {
				roles = append(roles, pqid(r))
			}
		}
		fmt.Fprintf(w, "CREATE POLICY %s ON %s.%s AS %s FOR %s TO %s", pqid(p[2].String), pqid(p[0].String), pqid(p[1].String), p[3].String, p[4].String, strings.Join(roles, ", "))
		if p[6].Valid {
			fmt.Fprintf(w, " USING (%s)", p[6].String)
		}
		if p[7].Valid {
			fmt.Fprintf(w, " WITH CHECK (%s)", p[7].String)
		}
		w.WriteString(";\n")
	}
	comments, err := q(`SELECT n.nspname, c.relname, a.attname, d.description, c.relkind FROM pg_description d
		JOIN pg_class c ON c.oid = d.objoid AND d.classoid = 'pg_class'::regclass JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = d.objsubid AND d.objsubid > 0
		WHERE ` + pgUserNS + ` AND c.relkind IN ('r','p','v','m') ORDER BY c.oid, d.objsubid`)
	if err != nil {
		return err
	}
	for _, c := range comments {
		if !whole && !keepTable(tables, c[0].String, c[1].String) {
			continue
		}
		obj := map[string]string{"r": "TABLE", "p": "TABLE", "v": "VIEW", "m": "MATERIALIZED VIEW"}[c[4].String]
		if c[2].Valid {
			fmt.Fprintf(w, "COMMENT ON COLUMN %s.%s.%s IS %s;\n", pqid(c[0].String), pqid(c[1].String), pqid(c[2].String), pqlit(c[3].String))
		} else {
			fmt.Fprintf(w, "COMMENT ON %s %s.%s IS %s;\n", obj, pqid(c[0].String), pqid(c[1].String), pqlit(c[3].String))
		}
	}
	return nil
}

func keepTable(tables []pgTable, schema, name string) bool {
	for _, t := range tables {
		if t.schema == schema && t.name == name {
			return true
		}
	}
	return false
}

func isPartitioned(tables []pgTable, schema, name string) bool {
	for _, t := range tables {
		if t.schema == schema && t.name == name {
			return t.kind == "p"
		}
	}
	return false
}

func firstWords(q string) string {
	f := strings.Fields(q)
	if len(f) > 4 {
		f = f[:4]
	}
	return strings.Join(f, " ")
}

// pgUnsupported names objects the built-in dump cannot write.
func pgUnsupported(q func(string, ...any) ([][]sql.NullString, error)) error {
	rows, err := q(`
		SELECT 'aggregate ' || p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.prokind = 'a' AND ` + pgUserNS + ` AND ` + pgExt("p") + `
		UNION ALL SELECT 'operator ' || o.oid::regoperator::text FROM pg_operator o JOIN pg_namespace n ON n.oid = o.oprnamespace WHERE ` + pgUserNS + ` AND ` + pgExt("o") + `
		UNION ALL SELECT 'foreign table ' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind = 'f' AND ` + pgUserNS + `
		UNION ALL SELECT 'rule ' || r.rulename || ' on ' || c.relname FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class JOIN pg_namespace n ON n.oid = c.relnamespace WHERE r.rulename <> '_RETURN' AND ` + pgUserNS + `
		UNION ALL SELECT 'event trigger ' || evtname FROM pg_event_trigger e WHERE ` + pgExt("e") + `
		UNION ALL SELECT 'publication ' || pubname FROM pg_publication
		UNION ALL SELECT 'large objects' WHERE EXISTS (SELECT 1 FROM pg_largeobject_metadata)
		UNION ALL SELECT 'collation ' || c.collname FROM pg_collation c JOIN pg_namespace n ON n.oid = c.collnamespace WHERE ` + pgUserNS + ` AND ` + pgExt("c") + `
		UNION ALL SELECT 'text search configuration ' || c.cfgname FROM pg_ts_config c JOIN pg_namespace n ON n.oid = c.cfgnamespace WHERE ` + pgUserNS + ` AND ` + pgExt("c") + `
		UNION ALL SELECT 'cast ' || format_type(c.castsource, NULL) || ' AS ' || format_type(c.casttarget, NULL) FROM pg_cast c WHERE c.oid >= 16384 AND ` + pgExt("c") + `
		UNION ALL SELECT 'range type ' || t.typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typtype IN ('r','m') AND ` + pgUserNS + ` AND ` + pgExt("t") + `
		UNION ALL SELECT 'inherited table ' || c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE NOT c.relispartition AND c.relkind = 'r' AND ` + pgUserNS + `
		LIMIT 20`)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	var names []string
	for _, r := range rows {
		names = append(names, r[0].String)
	}
	return &UnsupportedError{Objects: names}
}

// UnsupportedError lists objects the built-in dump does not write.
type UnsupportedError struct{ Objects []string }

func (e *UnsupportedError) Error() string {
	return "the built-in dump does not write " + strings.Join(e.Objects, ", ")
}

func pgTables(q func(string, ...any) ([][]sql.NullString, error), only []string) ([]pgTable, error) {
	rows, err := q(`SELECT c.oid, n.nspname, c.relname, c.relkind, c.relpersistence = 'u', c.relispartition,
		COALESCE((SELECT pn.nspname || '.' || pc.relname FROM pg_inherits i JOIN pg_class pc ON pc.oid = i.inhparent
		  JOIN pg_namespace pn ON pn.oid = pc.relnamespace WHERE i.inhrelid = c.oid LIMIT 1), ''),
		COALESCE(pg_get_expr(c.relpartbound, c.oid), ''), CASE WHEN c.relkind = 'p' THEN pg_get_partkeydef(c.oid) ELSE '' END,
		c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r','p') AND ` + pgUserNS + ` AND ` + pgExt("c") + `
		ORDER BY c.relispartition, c.oid`)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, t := range only {
		if !strings.Contains(t, ".") {
			t = "public." + t
		}
		want[t] = true
	}
	var out []pgTable
	for _, r := range rows {
		var oid uint32
		fmt.Sscan(r[0].String, &oid)
		t := pgTable{oid: oid, schema: r[1].String, name: r[2].String, kind: r[3].String, unlogged: r[4].String == "true",
			isPart: r[5].String == "true", parent: r[6].String, bound: r[7].String, partKey: r[8].String,
			rls: r[9].String == "true", forceRLS: r[10].String == "true"}
		if len(want) > 0 && !want[t.schema+"."+t.name] {
			continue
		}
		delete(want, t.schema+"."+t.name)
		out = append(out, t)
	}
	for t := range want {
		return nil, fmt.Errorf("no table %q", t)
	}
	return out, nil
}

// pgPreamble writes extensions, schemas, types and functions.
func pgPreamble(q func(string, ...any) ([][]sql.NullString, error), w *bufio.Writer) error {
	schemas, err := q(`SELECT n.nspname FROM pg_namespace n WHERE ` + pgUserNS + ` AND n.nspname <> 'public' AND ` + pgExt("n") + ` ORDER BY n.oid`)
	if err != nil {
		return err
	}
	for _, s := range schemas {
		fmt.Fprintf(w, "CREATE SCHEMA IF NOT EXISTS %s;\n", pqid(s[0].String))
	}
	exts, err := q(`SELECT e.extname, n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname <> 'plpgsql' ORDER BY e.oid`)
	if err != nil {
		return err
	}
	for _, e := range exts {
		fmt.Fprintf(w, "CREATE EXTENSION IF NOT EXISTS %s WITH SCHEMA %s;\n", pqid(e[0].String), pqid(e[1].String))
	}
	enums, err := q(`SELECT format_type(t.oid, NULL), string_agg(quote_literal(e.enumlabel), ', ' ORDER BY e.enumsortorder)
		FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE ` + pgUserNS + ` AND ` + pgExt("t") + ` GROUP BY t.oid ORDER BY t.oid`)
	if err != nil {
		return err
	}
	for _, e := range enums {
		fmt.Fprintf(w, "CREATE TYPE %s AS ENUM (%s);\n", e[0].String, e[1].String)
	}
	comps, err := q(`SELECT format_type(t.oid, NULL), string_agg(quote_ident(a.attname) || ' ' || format_type(a.atttypid, a.atttypmod), ', ' ORDER BY a.attnum)
		FROM pg_type t JOIN pg_class c ON c.oid = t.typrelid AND c.relkind = 'c' JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typtype = 'c' AND ` + pgUserNS + ` AND ` + pgExt("t") + ` GROUP BY t.oid ORDER BY t.oid`)
	if err != nil {
		return err
	}
	for _, c := range comps {
		fmt.Fprintf(w, "CREATE TYPE %s AS (%s);\n", c[0].String, c[1].String)
	}
	doms, err := q(`SELECT t.oid, format_type(t.oid, NULL), format_type(t.typbasetype, t.typtypmod), t.typnotnull, t.typdefault,
		COALESCE((SELECT string_agg('CONSTRAINT ' || quote_ident(con.conname) || ' ' || pg_get_constraintdef(con.oid), ' ') FROM pg_constraint con WHERE con.contypid = t.oid), '')
		FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typtype = 'd' AND ` + pgUserNS + ` AND ` + pgExt("t") + ` ORDER BY t.oid`)
	if err != nil {
		return err
	}
	for _, d := range doms {
		s := fmt.Sprintf("CREATE DOMAIN %s AS %s", d[1].String, d[2].String)
		if d[4].Valid {
			s += " DEFAULT " + d[4].String
		}
		if d[3].String == "true" {
			s += " NOT NULL"
		}
		if d[5].String != "" {
			s += " " + d[5].String
		}
		w.WriteString(s + ";\n")
	}
	funcs, err := pgFunctions(q, false)
	if err != nil {
		return err
	}
	for _, f := range funcs {
		fmt.Fprintf(w, "%s;\n\n", f)
	}
	w.WriteString("\n")
	return nil
}

// pgFuncLate: a function that uses a table, view or a table's row type (in
// its arguments, result or SQL-standard body) can only be made after them.
const pgFuncLate = `(p.prosqlbody IS NOT NULL OR EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid
	AND (d.refclassid = 'pg_class'::regclass OR (d.refclassid = 'pg_type'::regclass AND EXISTS (SELECT 1 FROM pg_type t
	  JOIN pg_class c ON c.oid = t.typrelid WHERE t.oid = d.refobjid AND c.relkind IN ('r','p','v','m'))))))`

// pgFunctions are the functions and procedures made before the tables
// (late false) or after them and the views (late true).
func pgFunctions(q func(string, ...any) ([][]sql.NullString, error), late bool) ([]string, error) {
	cond := "NOT " + pgFuncLate
	if late {
		cond = pgFuncLate
	}
	rows, err := q(`SELECT pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE p.prokind IN ('f','p','w') AND ` + pgUserNS + ` AND ` + pgExt("p") + ` AND ` + cond + ` ORDER BY p.oid`)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		out = append(out, strings.TrimSpace(r[0].String))
	}
	return out, nil
}

func pgCreateTable(q func(string, ...any) ([][]sql.NullString, error), t pgTable, w *bufio.Writer) error {
	if t.isPart {
		p := strings.SplitN(t.parent, ".", 2)
		fmt.Fprintf(w, "CREATE TABLE %s PARTITION OF %s.%s %s", t.qname(), pqid(p[0]), pqid(p[1]), t.bound)
		if t.kind == "p" {
			fmt.Fprintf(w, " PARTITION BY %s", t.partKey)
		}
		w.WriteString(";\n\n")
		return nil
	}
	cols, err := q(`SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, pg_get_expr(d.adbin, d.adrelid), a.attidentity, a.attgenerated,
		CASE WHEN a.attcollation <> t.typcollation AND a.attcollation <> 0 THEN (SELECT quote_ident(cn.nspname) || '.' || quote_ident(co.collname)
		  FROM pg_collation co JOIN pg_namespace cn ON cn.oid = co.collnamespace WHERE co.oid = a.attcollation) END
		FROM pg_attribute a JOIN pg_type t ON t.oid = a.atttypid LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`, t.oid)
	if err != nil {
		return err
	}
	var defs []string
	for _, c := range cols {
		s := "    " + pqid(c[0].String) + " " + c[1].String
		if c[6].Valid {
			s += " COLLATE " + c[6].String
		}
		switch {
		case c[5].String == "s":
			s += " GENERATED ALWAYS AS (" + c[3].String + ") STORED"
		case c[4].String == "a":
			s += " GENERATED ALWAYS AS IDENTITY"
		case c[4].String == "d":
			s += " GENERATED BY DEFAULT AS IDENTITY"
		case c[3].Valid:
			s += " DEFAULT " + c[3].String
		}
		if c[2].String == "true" {
			s += " NOT NULL"
		}
		defs = append(defs, s)
	}
	unlogged := ""
	if t.unlogged {
		unlogged = "UNLOGGED "
	}
	fmt.Fprintf(w, "CREATE %sTABLE %s (\n%s\n)", unlogged, t.qname(), strings.Join(defs, ",\n"))
	if t.kind == "p" {
		fmt.Fprintf(w, " PARTITION BY %s", t.partKey)
	}
	w.WriteString(";\n\n")
	return nil
}

// rawPg gives COPY TO STDOUT on the session's own connection (so it reads
// inside the dump's snapshot).
func rawPg(conn *sql.Conn) (func(ctx context.Context, w *bufio.Writer, sql string) error, error) {
	return func(ctx context.Context, w *bufio.Writer, query string) error {
		return conn.Raw(func(dc any) error {
			c, ok := dc.(*stdlib.Conn)
			if !ok {
				return fmt.Errorf("not a PostgreSQL connection")
			}
			_, err := c.Conn().PgConn().CopyTo(ctx, w, query)
			return err
		})
	}, nil
}
