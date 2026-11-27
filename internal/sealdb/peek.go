package sealdb

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Reading a store without its key: its readable settings, and rolling back
// a write step that a crash cut off.

// Peek reads the readable settings of the store at path (format, key mode,
// salt) without a key and without making the file. A missing file is
// os.ErrNotExist.
func Peek(ctx context.Context, path string) (map[string]string, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout("+strconv.Itoa(int(busyTimeout/time.Millisecond))+")")
	dsn, err := fileURI(path, q)
	if err != nil {
		return nil, err
	}
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	defer sdb.Close()
	rows, err := sdb.QueryContext(ctx, `SELECT k,v FROM meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, rows.Err()
}

// JournalLeft reports whether store.db-journal is next to the store at
// path: a write step at work, or one that a crash cut off (a hot
// journal), which only a read-write open rolls back.
func JournalLeft(path string) bool {
	fi, err := os.Stat(path + "-journal")
	return err == nil && fi.Size() > 0
}

// RollBack opens the store at path read-write once and reads its header,
// which makes SQLite roll back a write step that a crash cut off; the
// read-only opens (Peek, OpenReadOnly) cannot, and fail on it. It needs no
// key, reads no record and never makes the file. The caller holds the
// store lock.
func RollBack(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	q := url.Values{}
	q.Set("mode", "rw")
	q.Add("_pragma", "busy_timeout("+strconv.Itoa(int(busyTimeout/time.Millisecond))+")")
	dsn, err := fileURI(path, q)
	if err != nil {
		return err
	}
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer sdb.Close()
	var n int
	return sdb.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master`).Scan(&n)
}
