package dbx

import (
	"context"
	"database/sql"
	"strings"
)

// ClickHouse's databases play the part of schemas: db schema lists the
// tables of every database but the system ones, with their engine, and a
// table asked for by name gets its columns, its keys (ORDER BY, PRIMARY
// KEY, PARTITION BY) and its data-skipping indexes.

func clickhouseSchema(ctx context.Context, tx *sql.Tx, names []string) ([]Table, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT database, name,
       multiIf(engine IN ('View', 'MaterializedView', 'LiveView', 'WindowView'), 'view', engine = 'Dictionary', 'dictionary', 'table'),
       engine, total_rows, sorting_key, primary_key, partition_key
FROM system.tables
WHERE database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema') AND NOT is_temporary
ORDER BY database, name`)
	if err != nil {
		return nil, err
	}
	type keys struct{ sorting, primary, partition string }
	var tables []Table
	var tkeys []keys
	for rows.Next() {
		var t Table
		var k keys
		var est sql.NullInt64
		if err := rows.Scan(&t.Schema, &t.Name, &t.Type, &t.Engine, &est, &k.sorting, &k.primary, &k.partition); err != nil {
			rows.Close()
			return nil, err
		}
		if est.Valid {
			t.RowEstimate = &est.Int64
		}
		if wanted(t, names) {
			tables = append(tables, t)
			tkeys = append(tkeys, k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(names) == 0 {
		return tables, err
	}
	for i := range tables {
		t := &tables[i]
		for _, k := range []struct{ name, expr string }{
			{"PARTITION BY", tkeys[i].partition}, {"ORDER BY", tkeys[i].sorting}, {"PRIMARY KEY", tkeys[i].primary},
		} {
			if k.expr != "" {
				t.Indexes = append(t.Indexes, Index{Name: strings.ToLower(k.name), Definition: k.name + " " + k.expr})
			}
		}
		if err := clickhouseDescribe(ctx, tx, t); err != nil {
			return nil, err
		}
	}
	return tables, nil
}

// clickhouseDescribe fills a table's columns and data-skipping indexes.
func clickhouseDescribe(ctx context.Context, tx *sql.Tx, t *Table) error {
	cols, err := tx.QueryContext(ctx, `
SELECT name, type, default_kind, default_expression, is_in_primary_key
FROM system.columns WHERE database = {p1:String} AND table = {p2:String} ORDER BY position`, t.Schema, t.Name)
	if err != nil {
		return err
	}
	for cols.Next() {
		var c TableColumn
		var kind, expr string
		var pk int64
		if err := cols.Scan(&c.Name, &c.Type, &kind, &expr, &pk); err != nil {
			cols.Close()
			return err
		}
		c.Nullable = strings.HasPrefix(strings.TrimPrefix(c.Type, "LowCardinality("), "Nullable(")
		c.PrimaryKey = pk == 1
		if kind != "" {
			d := expr
			if kind != "DEFAULT" { // MATERIALIZED, ALIAS, EPHEMERAL: computed, not a default
				d = kind + " " + expr
			}
			c.Default = &d
		}
		t.Columns = append(t.Columns, c)
	}
	cols.Close()
	if err := cols.Err(); err != nil {
		return err
	}
	idx, err := tx.QueryContext(ctx, `
SELECT name, concat('INDEX ', name, ' ', expr, ' TYPE ', type_full, ' GRANULARITY ', toString(granularity))
FROM system.data_skipping_indices WHERE database = {p1:String} AND table = {p2:String} ORDER BY name`, t.Schema, t.Name)
	if chCode(err) == 497 { // a user without SELECT on system tables still gets the columns
		return nil
	}
	if err != nil {
		return err
	}
	defer idx.Close()
	for idx.Next() {
		var ix Index
		if err := idx.Scan(&ix.Name, &ix.Definition); err != nil {
			return err
		}
		t.Indexes = append(t.Indexes, ix)
	}
	return idx.Err()
}
