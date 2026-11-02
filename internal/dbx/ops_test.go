package dbx

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func sqliteDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)`,
		`CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestSQLiteInfoSizesAndForeignKeys(t *testing.T) {
	db := sqliteDB(t)
	ctx := context.Background()
	info, err := Info(ctx, db, "sqlite", time.Second)
	if err != nil || info["version"] == nil || info["size_bytes"] == nil {
		t.Fatalf("info: %v %v", info, err)
	}
	sizes, err := Sizes(ctx, db, "sqlite", 5, time.Second)
	if err != nil || len(sizes["databases"].([]map[string]any)) != 1 {
		t.Fatalf("sizes: %v %v", sizes, err)
	}
	if _, err := Activity(ctx, db, "sqlite", false, time.Second); err == nil {
		t.Error("activity on sqlite must say it does not apply")
	}
	tables, err := Schema(ctx, db, "sqlite", []string{"orders"}, time.Second)
	if err != nil || len(tables) != 1 || len(tables[0].Constraints) != 1 {
		t.Fatalf("schema: %+v %v", tables, err)
	}
	if c := tables[0].Constraints[0]; c.Type != "foreign key" || c.Definition != "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE NO ACTION" {
		t.Errorf("constraint: %+v", c)
	}
}
