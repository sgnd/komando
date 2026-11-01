package dbx

import (
	"context"
	"database/sql"
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
	RowEstimate *int64        `json:"row_estimate,omitempty"`
	Columns     []TableColumn `json:"columns,omitempty"`
	Indexes     []Index       `json:"indexes,omitempty"`
}

type TableColumn struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"`
	Nullable   bool    `json:"nullable"`
	Default    *string `json:"default,omitempty"`
	PrimaryKey bool    `json:"primary_key,omitempty"`
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
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: kind != "sqlite"})
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
		tables, err = mysqlSchema(tx, names)
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
				return nil, out.Errf(out.ExitNotFound, "TABLE_NOT_FOUND", "run `komando db schema CONN` to list tables", "table %q not found", n)
			}
		}
	}
	if tables == nil {
		tables = []Table{}
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
       COALESCE(a.attnum = ANY (i.indkey), false)
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
			if err := cols.Scan(&c.Name, &c.Type, &c.Nullable, &c.Default, &c.PrimaryKey); err != nil {
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
