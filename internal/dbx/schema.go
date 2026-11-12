package dbx

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// Table describes one table or view. Columns and Indexes are filled only
// when the table was asked for by name.
type Table struct {
	Schema      string        `json:"schema,omitempty"`
	Name        string        `json:"name"`
	Type        string        `json:"type"`
	Engine      string        `json:"engine,omitempty"` // ClickHouse: MergeTree, ReplicatedMergeTree, View, ...
	RowEstimate *int64        `json:"row_estimate,omitempty"`
	Columns     []TableColumn `json:"columns,omitempty"`
	Indexes     []Index       `json:"indexes,omitempty"`
	// Constraints are foreign keys, checks and unique constraints.
	Constraints []Constraint `json:"constraints,omitempty"`
}

type Constraint struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // foreign key | check | unique | exclusion
	Definition string `json:"definition"`
}

type TableColumn struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Nullable   bool    `json:"nullable"`
	Default    *string `json:"default,omitempty"`
	PrimaryKey bool    `json:"primary_key,omitempty"`
	// Identity says the database numbers the column itself: "auto_increment"
	// (MySQL, SQLite AUTOINCREMENT), "always" or "by default" (PostgreSQL),
	// "identity" (SQL Server).
	Identity string `json:"identity,omitempty"`
}

type Index struct {
	Name       string `json:"name"`
	Definition string `json:"definition,omitempty"`
}

// Schema lists tables, or describes the named ones (NAME or SCHEMA.NAME).
// It runs in a read-only transaction.
func Schema(ctx context.Context, db *sql.DB, kind string, names []string, timeout time.Duration) ([]Table, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if kind == "oracle" || kind == "snowflake" { // unquoted names are upper case
		names = oracleNames(names)
	}
	if kind == "bigquery" { // from the API, not a transaction
		return bigquerySchema(ctx, db, names)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: readOnlyTx(kind, false)})
	if err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	defer tx.Rollback()
	var tables []Table
	switch kind {
	case "postgres":
		tables, err = pgSchema(ctx, tx, names)
	case "sqlite":
		tables, err = sqliteSchema(ctx, tx, names)
	case "mysql":
		tables, err = mysqlSchema(ctx, tx, names)
	case "sqlserver":
		tables, err = mssqlSchema(ctx, tx, names)
	case "oracle":
		tables, err = oracleSchema(ctx, tx, names)
	case "clickhouse":
		tables, err = clickhouseSchema(ctx, tx, names)
	case "snowflake":
		tables, err = snowflakeSchema(ctx, tx, names)
	}
	if err == nil && len(names) > 0 {
		err = addConstraints(ctx, tx, kind, tables)
	}
	if err != nil {
		return nil, queryErr(kind, ctx, err)
	}
	if len(names) > 0 {
		for _, n := range names {
			found := false
			for _, t := range tables {
				if t.Name == n || t.Schema+"."+t.Name == n {
					found = true
				}
			}
			if !found {
				return nil, out.Errf(out.ExitNotFound, "TABLE_NOT_FOUND", "run `komando db schema CONN` to list tables", "no table named %q", n)
			}
		}
	}
	if tables == nil {
		tables = []Table{}
	}
	if len(names) > 0 { // in the order they were asked for
		pos := func(t Table) int {
			for i, n := range names {
				if t.Name == n || t.Schema+"."+t.Name == n {
					return i
				}
			}
			return len(names)
		}
		sort.SliceStable(tables, func(i, j int) bool { return pos(tables[i]) < pos(tables[j]) })
	}
	return tables, nil
}

// wanted filters tables to the requested names (all when names is empty).
func wanted(t Table, names []string) bool {
	if len(names) == 0 {
		return true
	}
	for _, n := range names {
		if t.Name == n || t.Schema+"."+t.Name == n {
			return true
		}
	}
	return false
}

func pgSchema(ctx context.Context, tx *sql.Tx, names []string) ([]Table, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT n.nspname, c.relname,
       CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view' WHEN 'f' THEN 'foreign table' ELSE 'table' END,
       CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	var tables []Table
	for rows.Next() {
		var t Table
		if err := rows.Scan(&t.Schema, &t.Name, &t.Type, &t.RowEstimate); err != nil {
			rows.Close()
			return nil, err
		}
		if wanted(t, names) {
			tables = append(tables, t)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(names) == 0 {
		return tables, err
	}
	for i := range tables {
		t := &tables[i]
		cols, err := tx.QueryContext(ctx, `
SELECT a.attname, format_type(a.atttypid, a.atttypmod), NOT a.attnotnull, pg_get_expr(d.adbin, d.adrelid),
       COALESCE(a.attnum = ANY (i.indkey), false),
       CASE a.attidentity WHEN 'a' THEN 'always' WHEN 'd' THEN 'by default' ELSE '' END
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
LEFT JOIN pg_index i ON i.indrelid = c.oid AND i.indisprimary
WHERE n.nspname = $1 AND c.relname = $2 AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum`, t.Schema, t.Name)
		if err != nil {
			return nil, err
		}
		for cols.Next() {
			var c TableColumn
			if err := cols.Scan(&c.Name, &c.Type, &c.Nullable, &c.Default, &c.PrimaryKey, &c.Identity); err != nil {
				cols.Close()
				return nil, err
			}
			t.Columns = append(t.Columns, c)
		}
		cols.Close()
		idx, err := tx.QueryContext(ctx, `SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = $1 AND tablename = $2 ORDER BY 1`, t.Schema, t.Name)
		if err != nil {
			return nil, err
		}
		for idx.Next() {
			var ix Index
			if err := idx.Scan(&ix.Name, &ix.Definition); err != nil {
				idx.Close()
				return nil, err
			}
			t.Indexes = append(t.Indexes, ix)
		}
		idx.Close()
	}
	return tables, nil
}

func sqliteSchema(ctx context.Context, tx *sql.Tx, names []string) ([]Table, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var tables []Table
	for rows.Next() {
		var t Table
		if err := rows.Scan(&t.Name, &t.Type); err != nil {
			rows.Close()
			return nil, err
		}
		if wanted(t, names) {
			tables = append(tables, t)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(names) == 0 {
		return tables, err
	}
	for i := range tables {
		t := &tables[i]
		cols, err := tx.QueryContext(ctx, `SELECT name, type, "notnull", dflt_value, pk FROM pragma_table_info(?)`, t.Name)
		if err != nil {
			return nil, err
		}
		for cols.Next() {
			var c TableColumn
			var notNull, pk int
			if err := cols.Scan(&c.Name, &c.Type, &notNull, &c.Default, &pk); err != nil {
				cols.Close()
				return nil, err
			}
			c.Type = strings.ToLower(c.Type)
			c.Nullable, c.PrimaryKey = notNull == 0 && pk == 0, pk > 0
			t.Columns = append(t.Columns, c)
		}
		cols.Close()
		var ddl string
		_ = tx.QueryRowContext(ctx, `SELECT COALESCE(sql, '') FROM sqlite_master WHERE name = ?`, t.Name).Scan(&ddl)
		if strings.Contains(strings.ToUpper(ddl), "AUTOINCREMENT") {
			for j := range t.Columns {
				if t.Columns[j].PrimaryKey && t.Columns[j].Type == "integer" {
					t.Columns[j].Identity = "auto_increment"
				}
			}
		}
		idx, err := tx.QueryContext(ctx, `SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE type = 'index' AND tbl_name = ? ORDER BY name`, t.Name)
		if err != nil {
			return nil, err
		}
		for idx.Next() {
			var ix Index
			if err := idx.Scan(&ix.Name, &ix.Definition); err != nil {
				idx.Close()
				return nil, err
			}
			t.Indexes = append(t.Indexes, ix)
		}
		idx.Close()
	}
	return tables, nil
}

// addConstraints fills Constraints of the described tables: what the table
// points at (foreign keys) and what it checks.
func addConstraints(ctx context.Context, tx *sql.Tx, kind string, tables []Table) error {
	for i := range tables {
		t := &tables[i]
		if t.Type != "table" {
			continue
		}
		var rows *sql.Rows
		var err error
		switch kind {
		case "postgres":
			rows, err = tx.QueryContext(ctx, `
SELECT conname, CASE contype WHEN 'f' THEN 'foreign key' WHEN 'c' THEN 'check' WHEN 'u' THEN 'unique' ELSE 'exclusion' END,
       pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = (quote_ident($1) || '.' || quote_ident($2))::regclass AND contype IN ('f', 'c', 'u', 'x')
ORDER BY 2, 1`, t.Schema, t.Name)
		case "mysql":
			rows, err = tx.QueryContext(ctx, `
SELECT k.constraint_name, 'foreign key',
       CONCAT('FOREIGN KEY (', GROUP_CONCAT(k.column_name ORDER BY k.ordinal_position SEPARATOR ', '), ') REFERENCES ',
              k.referenced_table_name, '(', GROUP_CONCAT(k.referenced_column_name ORDER BY k.ordinal_position SEPARATOR ', '), ')',
              ' ON DELETE ', r.delete_rule, ' ON UPDATE ', r.update_rule)
FROM information_schema.key_column_usage k
JOIN information_schema.referential_constraints r
  ON r.constraint_schema = k.constraint_schema AND r.constraint_name = k.constraint_name
WHERE k.table_schema = DATABASE() AND k.table_name = ? AND k.referenced_table_name IS NOT NULL
GROUP BY k.constraint_name, k.referenced_table_name, r.delete_rule, r.update_rule
ORDER BY 1`, t.Name)
		case "sqlite":
			rows, err = tx.QueryContext(ctx, `
SELECT 'fk_' || id, 'foreign key',
       'FOREIGN KEY (' || group_concat("from", ', ') || ') REFERENCES ' || "table" || '(' || group_concat("to", ', ') || ')' ||
       ' ON DELETE ' || on_delete || ' ON UPDATE ' || on_update
FROM pragma_foreign_key_list(?) GROUP BY id ORDER BY id`, t.Name)
		case "sqlserver":
			rows, err = tx.QueryContext(ctx, mssqlConstraints, t.Schema, t.Name)
		case "oracle":
			rows, err = tx.QueryContext(ctx, oracleConstraints, t.Schema, t.Name)
		default:
			return nil
		}
		if err != nil {
			return err
		}
		for rows.Next() {
			var c Constraint
			if err := rows.Scan(&c.Name, &c.Type, &c.Definition); err != nil {
				rows.Close()
				return err
			}
			t.Constraints = append(t.Constraints, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	return nil
}
