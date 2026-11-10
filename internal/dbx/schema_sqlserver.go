package dbx

import (
	"context"
	"database/sql"
)

// mssqlType spells a column's type with its size: nvarchar(50),
// varchar(max), decimal(10,2), datetime2(7).
const mssqlType = `TYPE_NAME(c.user_type_id) + CASE
  WHEN TYPE_NAME(c.user_type_id) IN ('varchar', 'char', 'varbinary', 'binary')
    THEN '(' + CASE c.max_length WHEN -1 THEN 'max' ELSE CAST(c.max_length AS varchar(10)) END + ')'
  WHEN TYPE_NAME(c.user_type_id) IN ('nvarchar', 'nchar')
    THEN '(' + CASE c.max_length WHEN -1 THEN 'max' ELSE CAST(c.max_length / 2 AS varchar(10)) END + ')'
  WHEN TYPE_NAME(c.user_type_id) IN ('decimal', 'numeric')
    THEN '(' + CAST(c.precision AS varchar(10)) + ',' + CAST(c.scale AS varchar(10)) + ')'
  WHEN TYPE_NAME(c.user_type_id) IN ('datetime2', 'time', 'datetimeoffset')
    THEN '(' + CAST(c.scale AS varchar(10)) + ')'
  ELSE '' END`

// mssqlObject is the object id of the table @p1.@p2.
const mssqlObject = `OBJECT_ID(QUOTENAME(@p1) + '.' + QUOTENAME(@p2))`

func mssqlSchema(ctx context.Context, tx *sql.Tx, names []string) ([]Table, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT s.name, o.name, CASE o.type WHEN 'V' THEN 'view' ELSE 'table' END,
       (SELECT SUM(p.rows) FROM sys.partitions p WHERE p.object_id = o.object_id AND p.index_id IN (0, 1))
FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id
WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0
ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	var tables []Table
	for rows.Next() {
		var t Table
		var est sql.NullInt64
		if err := rows.Scan(&t.Schema, &t.Name, &t.Type, &est); err != nil {
			rows.Close()
			return nil, err
		}
		if est.Valid {
			t.RowEstimate = &est.Int64
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
		if err := mssqlDescribe(ctx, tx, &tables[i]); err != nil {
			return nil, err
		}
	}
	return tables, nil
}

// mssqlDescribe fills a table's columns and indexes.
func mssqlDescribe(ctx context.Context, tx *sql.Tx, t *Table) error {
	cols, err := tx.QueryContext(ctx, `
SELECT c.name, `+mssqlType+`, c.is_nullable, OBJECT_DEFINITION(c.default_object_id),
       CAST(CASE WHEN EXISTS (SELECT 1 FROM sys.index_columns ic JOIN sys.indexes i ON i.object_id = ic.object_id AND i.index_id = ic.index_id
                              WHERE i.is_primary_key = 1 AND ic.object_id = c.object_id AND ic.column_id = c.column_id) THEN 1 ELSE 0 END AS bit),
       c.is_identity
FROM sys.columns c WHERE c.object_id = `+mssqlObject+` ORDER BY c.column_id`, t.Schema, t.Name)
	if err != nil {
		return err
	}
	for cols.Next() {
		var c TableColumn
		var identity bool
		if err := cols.Scan(&c.Name, &c.Type, &c.Nullable, &c.Default, &c.PrimaryKey, &identity); err != nil {
			cols.Close()
			return err
		}
		if identity {
			c.Identity = "identity"
		}
		t.Columns = append(t.Columns, c)
	}
	cols.Close()
	if err := cols.Err(); err != nil {
		return err
	}
	idx, err := tx.QueryContext(ctx, `
SELECT i.name,
       CASE WHEN i.is_primary_key = 1 THEN 'PRIMARY KEY ' WHEN i.is_unique = 1 THEN 'UNIQUE ' ELSE '' END + i.type_desc COLLATE DATABASE_DEFAULT + ' INDEX ' + i.name + ' (' +
       STUFF((SELECT ', ' + c.name + CASE WHEN ic.is_descending_key = 1 THEN ' DESC' ELSE '' END
              FROM sys.index_columns ic JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
              WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id AND ic.is_included_column = 0
              ORDER BY ic.key_ordinal FOR XML PATH(''), TYPE).value('.', 'nvarchar(max)'), 1, 2, '') + ')'
FROM sys.indexes i WHERE i.object_id = `+mssqlObject+` AND i.index_id > 0 ORDER BY i.name`, t.Schema, t.Name)
	if err != nil {
		return err
	}
	defer idx.Close()
	for idx.Next() {
		var ix Index
		var def sql.NullString
		if err := idx.Scan(&ix.Name, &def); err != nil {
			return err
		}
		ix.Definition = def.String
		t.Indexes = append(t.Indexes, ix)
	}
	return idx.Err()
}

// mssqlConstraints are a table's foreign keys and checks.
const mssqlConstraints = `
SELECT fk.name, 'foreign key',
       'FOREIGN KEY (' + STUFF((SELECT ', ' + COL_NAME(k.parent_object_id, k.parent_column_id) FROM sys.foreign_key_columns k
                                WHERE k.constraint_object_id = fk.object_id ORDER BY k.constraint_column_id FOR XML PATH(''), TYPE).value('.', 'nvarchar(max)'), 1, 2, '') +
       ') REFERENCES ' + OBJECT_SCHEMA_NAME(fk.referenced_object_id) + '.' + OBJECT_NAME(fk.referenced_object_id) + '(' +
       STUFF((SELECT ', ' + COL_NAME(k.referenced_object_id, k.referenced_column_id) FROM sys.foreign_key_columns k
              WHERE k.constraint_object_id = fk.object_id ORDER BY k.constraint_column_id FOR XML PATH(''), TYPE).value('.', 'nvarchar(max)'), 1, 2, '') +
       ') ON DELETE ' + REPLACE(fk.delete_referential_action_desc COLLATE DATABASE_DEFAULT, '_', ' ') + ' ON UPDATE ' + REPLACE(fk.update_referential_action_desc COLLATE DATABASE_DEFAULT, '_', ' ')
FROM sys.foreign_keys fk WHERE fk.parent_object_id = ` + mssqlObject + `
UNION ALL
SELECT cc.name, 'check', 'CHECK ' + cc.definition FROM sys.check_constraints cc WHERE cc.parent_object_id = ` + mssqlObject + `
ORDER BY 2, 1`
