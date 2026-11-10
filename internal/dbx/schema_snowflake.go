package dbx

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Snowflake's tables come from the current database's INFORMATION_SCHEMA
// (the database in the conn URL): db schema lists the tables and views of
// every schema there, and a table asked for by name gets its columns, its
// primary key and its clustering key.

const (
	sfSchemaList = `
SELECT table_schema, table_name, CASE WHEN table_type LIKE '%VIEW' THEN 'view' ELSE 'table' END, row_count, clustering_key
FROM INFORMATION_SCHEMA.TABLES WHERE table_schema <> 'INFORMATION_SCHEMA'
ORDER BY 1, 2`
	// a column's type with its size: NUMBER(10,2), VARCHAR(100)
	sfColumnsSQL = `
SELECT column_name, CASE
         WHEN data_type = 'NUMBER' THEN 'NUMBER(' || numeric_precision || ',' || numeric_scale || ')'
         WHEN data_type = 'TEXT' THEN 'VARCHAR(' || character_maximum_length || ')'
         ELSE data_type END,
       is_nullable, column_default, is_identity
FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position`
)

func snowflakeSchema(ctx context.Context, tx *sql.Tx, names []string) ([]Table, error) {
	rows, err := tx.QueryContext(ctx, sfSchemaList)
	if err != nil {
		return nil, err
	}
	var tables []Table
	var clusters []sql.NullString
	for rows.Next() {
		var t Table
		var est sql.NullInt64
		var cluster sql.NullString
		if err := rows.Scan(&t.Schema, &t.Name, &t.Type, &est, &cluster); err != nil {
			rows.Close()
			return nil, err
		}
		if est.Valid {
			t.RowEstimate = &est.Int64
		}
		if wanted(t, names) {
			tables = append(tables, t)
			clusters = append(clusters, cluster)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(names) == 0 {
		return tables, err
	}
	for i := range tables {
		t := &tables[i]
		if c := clusters[i]; c.Valid && c.String != "" {
			t.Indexes = append(t.Indexes, Index{Name: "cluster by", Definition: "CLUSTER BY " + strings.TrimPrefix(c.String, "LINEAR")})
		}
		if err := snowflakeColumns(ctx, tx, t); err != nil {
			return nil, err
		}
	}
	return tables, nil
}

// snowflakeColumns fills a table's columns and marks its primary key
// (SHOW PRIMARY KEYS; a role that may not see it gets the columns alone).
func snowflakeColumns(ctx context.Context, tx *sql.Tx, t *Table) error {
	cols, err := tx.QueryContext(ctx, sfColumnsSQL, t.Schema, t.Name)
	if err != nil {
		return err
	}
	for cols.Next() {
		var c TableColumn
		var nullable, identity string
		var def sql.NullString
		if err := cols.Scan(&c.Name, &c.Type, &nullable, &def, &identity); err != nil {
			cols.Close()
			return err
		}
		c.Nullable = nullable == "YES"
		if def.Valid {
			c.Default = &def.String
		}
		if identity == "YES" {
			c.Identity = "identity"
		}
		t.Columns = append(t.Columns, c)
	}
	cols.Close()
	if err := cols.Err(); err != nil {
		return err
	}
	q := func(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
	keys, err := rowsOf(ctx, tx, "SHOW PRIMARY KEYS IN TABLE "+q(t.Schema)+"."+q(t.Name))
	if err != nil {
		return nil
	}
	for _, k := range keys {
		for i := range t.Columns {
			if t.Columns[i].Name == fmt.Sprint(k["column_name"]) {
				t.Columns[i].PrimaryKey = true
			}
		}
	}
	return nil
}
