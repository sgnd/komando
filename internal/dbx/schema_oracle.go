package dbx

import (
	"context"
	"database/sql"
	"strings"
)

// Oracle's schemas are its users: db schema lists the tables and views of
// every user that is not Oracle's own (ORACLE_MAINTAINED = 'N').

// oracleNames spells table names the way Oracle stores them: a name
// written without capitals is upper case, as Oracle reads it unquoted.
func oracleNames(names []string) []string {
	res := make([]string, len(names))
	for i, n := range names {
		if n == strings.ToLower(n) {
			n = strings.ToUpper(n)
		}
		res[i] = n
	}
	return res
}

// oracleType spells a column's type with its size: VARCHAR2(50 CHAR),
// NUMBER(10,2), RAW(16).
const oracleType = `c.data_type || CASE
  WHEN c.data_type IN ('VARCHAR2', 'CHAR') THEN '(' || c.char_length || CASE c.char_used WHEN 'C' THEN ' CHAR' END || ')'
  WHEN c.data_type IN ('NVARCHAR2', 'NCHAR') THEN '(' || c.char_length || ')'
  WHEN c.data_type = 'RAW' THEN '(' || c.data_length || ')'
  WHEN c.data_type = 'NUMBER' AND c.data_precision IS NOT NULL THEN '(' || c.data_precision || CASE WHEN c.data_scale > 0 THEN ',' || c.data_scale END || ')'
  WHEN c.data_type = 'NUMBER' AND c.data_scale = 0 THEN '(*,0)'
  END`

func oracleSchema(ctx context.Context, tx *sql.Tx, names []string) ([]Table, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT o.owner, o.object_name, CASE o.object_type WHEN 'VIEW' THEN 'view' ELSE 'table' END, t.num_rows
FROM all_objects o
JOIN all_users u ON u.username = o.owner AND u.oracle_maintained = 'N'
LEFT JOIN all_tables t ON t.owner = o.owner AND t.table_name = o.object_name
WHERE o.object_type IN ('TABLE', 'VIEW') AND o.object_name NOT LIKE 'BIN$%' AND o.generated = 'N'
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
		if err := oracleDescribe(ctx, tx, &tables[i]); err != nil {
			return nil, err
		}
	}
	return tables, nil
}

// oracleDescribe fills a table's columns and indexes.
func oracleDescribe(ctx context.Context, tx *sql.Tx, t *Table) error {
	cols, err := tx.QueryContext(ctx, `
SELECT c.column_name, `+oracleType+`, c.nullable, c.data_default,
       CASE WHEN EXISTS (SELECT 1 FROM all_constraints k JOIN all_cons_columns kc ON kc.owner = k.owner AND kc.constraint_name = k.constraint_name
                         WHERE k.owner = c.owner AND k.table_name = c.table_name AND k.constraint_type = 'P' AND kc.column_name = c.column_name)
            THEN 1 ELSE 0 END,
       LOWER(i.generation_type)
FROM all_tab_columns c
LEFT JOIN all_tab_identity_cols i ON i.owner = c.owner AND i.table_name = c.table_name AND i.column_name = c.column_name
WHERE c.owner = :1 AND c.table_name = :2 ORDER BY c.column_id`, t.Schema, t.Name)
	if err != nil {
		return err
	}
	for cols.Next() {
		var c TableColumn
		var nullable string
		var def, identity sql.NullString
		var pk int
		if err := cols.Scan(&c.Name, &c.Type, &nullable, &def, &pk, &identity); err != nil {
			cols.Close()
			return err
		}
		c.Nullable, c.PrimaryKey, c.Identity = nullable == "Y", pk == 1, identity.String
		if d := strings.TrimSpace(def.String); def.Valid && d != "" && !identity.Valid {
			c.Default = &d
		}
		t.Columns = append(t.Columns, c)
	}
	cols.Close()
	if err := cols.Err(); err != nil {
		return err
	}
	idx, err := tx.QueryContext(ctx, `
SELECT i.index_name,
       CASE WHEN EXISTS (SELECT 1 FROM all_constraints k WHERE k.owner = i.table_owner AND k.table_name = i.table_name
                         AND k.constraint_type = 'P' AND k.index_name = i.index_name) THEN 'PRIMARY KEY '
            WHEN i.uniqueness = 'UNIQUE' THEN 'UNIQUE ' END ||
       'INDEX ' || i.index_name || ' (' ||
       (SELECT LISTAGG(ic.column_name || CASE ic.descend WHEN 'DESC' THEN ' DESC' END, ', ') WITHIN GROUP (ORDER BY ic.column_position)
        FROM all_ind_columns ic WHERE ic.index_owner = i.owner AND ic.index_name = i.index_name) || ')'
FROM all_indexes i WHERE i.table_owner = :1 AND i.table_name = :2 AND i.index_type <> 'LOB' ORDER BY i.index_name`, t.Schema, t.Name)
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

// oracleConstraints are a table's foreign keys, checks and unique
// constraints (not the NOT NULL checks Oracle names itself).
const oracleConstraints = `
SELECT k.constraint_name, CASE k.constraint_type WHEN 'R' THEN 'foreign key' WHEN 'C' THEN 'check' ELSE 'unique' END,
       CASE k.constraint_type
         WHEN 'C' THEN 'CHECK (' || k.search_condition_vc || ')'
         WHEN 'U' THEN 'UNIQUE (' || (SELECT LISTAGG(c.column_name, ', ') WITHIN GROUP (ORDER BY c.position) FROM all_cons_columns c
                                      WHERE c.owner = k.owner AND c.constraint_name = k.constraint_name) || ')'
         ELSE 'FOREIGN KEY (' || (SELECT LISTAGG(c.column_name, ', ') WITHIN GROUP (ORDER BY c.position) FROM all_cons_columns c
                                  WHERE c.owner = k.owner AND c.constraint_name = k.constraint_name) ||
              ') REFERENCES ' || r.owner || '.' || r.table_name || '(' ||
              (SELECT LISTAGG(c.column_name, ', ') WITHIN GROUP (ORDER BY c.position) FROM all_cons_columns c
               WHERE c.owner = r.owner AND c.constraint_name = r.constraint_name) || ') ON DELETE ' || k.delete_rule
       END
FROM all_constraints k
LEFT JOIN all_constraints r ON r.owner = k.r_owner AND r.constraint_name = k.r_constraint_name
WHERE k.owner = :1 AND k.table_name = :2 AND k.constraint_type IN ('R', 'C', 'U')
  AND NOT (k.constraint_type = 'C' AND k.generated = 'GENERATED NAME' AND k.search_condition_vc LIKE '% IS NOT NULL')
ORDER BY 2, 1`
