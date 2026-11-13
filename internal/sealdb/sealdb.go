// Package sealdb is komando's local store: one SQLite file whose records are
// sealed rows (package sealrow).
//
// Readable columns are only a random ID, the type, the version, the change
// time and the deletion marker. Everything else, names included, is sealed.
//
// Several processes (the CLI, its background processes, the desktop app)
// share the file through SQLite's own locking: a write takes the write
// lock at its start (BEGIN IMMEDIATE) and waits up to BusyTimeout when
// another writer holds it. The rollback journal keeps the store one file,
// and every commit is flushed fully to disk (F_FULLFSYNC on macOS).
// Freed space is zeroed (secure_delete), so a deleted record or one sealed
// under an old key leaves no copy in the file.
//
// The deletion marker and the change time are also inside the seal, so
// editing those columns makes the row fail to open. Audit entries are bound
// to their sequence number, so a removed or moved entry shows as a gap.
//
// A row replaced with an older sealed copy of itself, a whole row removed,
// or the last audit entries cut off are caught by the index kept in the
// generation record (index.go, audit.go). An old copy of the whole store
// is caught by the generation number also kept in the OS keychain
// (section 16).
//
// Every step first checks that its key still opens the store: another
// process may have changed the key (Rekey) since this one opened it, and a
// write sealed with the old key would make the store unreadable. Such a
// step stops with ErrKeyChanged; the caller opens the store again.
//
// A View or Update called from inside another step, on the same goroutine,
// joins that step: a write runs in a savepoint of it, so it is kept or
// undone with the outer step, and its own error undoes only its part. An
// Update inside a View, or a Backup inside any step, returns ErrNested.
//
// The package reads no environment and no global state: the caller passes
// the path and the key.
package sealdb

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/sgnd/komando/internal/sealrow"
)

// Format is the database format this komando writes. A file with a higher
// number was made by a newer komando.
const Format = 1

// BusyTimeout is how long a writer waits for another writer.
const BusyTimeout = 10 * time.Second

var (
	// ErrNewerFormat: the file was made by a newer komando.
	ErrNewerFormat = errors.New("sealdb: store made by a newer komando; update komando")
	// ErrNotFound: no record with that ID.
	ErrNotFound = errors.New("sealdb: record not found")
	// ErrReadOnly: a change inside View.
	ErrReadOnly = errors.New("sealdb: change inside a read step")
	// ErrNested: a DB method called from inside View or Update.
	ErrNested = errors.New("sealdb: store used from inside its own read or write step")
	// ErrTampered: a readable column does not match what was sealed, or an
	// audit entry is missing.
	ErrTampered = errors.New("sealdb: store was changed outside komando")
	// ErrWrongKey: the store was sealed with another key.
	ErrWrongKey = errors.New("sealdb: the key does not open this store")
	// ErrKeyChanged: another process changed the store's key after this
	// handle was opened. Close it and open the store with the new key.
	ErrKeyChanged = errors.New("sealdb: the store's key was changed by another komando; open it again")
)

// keycheckID is a record every store holds from its start, so a wrong key
// is told apart from a damaged row.
const keycheckID, keycheckType = "keycheck", "keycheck"

const schema = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS records (
	id      TEXT PRIMARY KEY,
	type    TEXT NOT NULL,
	version INTEGER NOT NULL,
	mtime   INTEGER NOT NULL,
	deleted INTEGER NOT NULL DEFAULT 0,
	data    BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS records_type ON records(type);
CREATE TABLE IF NOT EXISTS audit (
	seq  INTEGER PRIMARY KEY AUTOINCREMENT,
	id   TEXT NOT NULL UNIQUE,
	time INTEGER NOT NULL,
	data BLOB NOT NULL
);`

// DB is an open store.
type DB struct {
	db  *sql.DB
	key *sealrow.Key
	// one step at a time in this process (the store has one connection);
	// holder is the goroutine running it, so a call from inside a step is
	// told apart from another goroutine waiting its turn
	mu     sync.Mutex
	holder atomic.Uint64
	cur    *Tx // the step holder is running
	depth  int // savepoints inside it
	opened bool

	// OnGeneration, when set, is told the new generation after each write
	// step that changed a record (the store keeps it in the keychain).
	OnGeneration func(uint64)
	// NoWrites, when set, is the error every write step fails with: the
	// store could not be checked, so it is read but never changed.
	NoWrites error
}

// fileURI makes the SQLite URI for path, escaped so that '?', '#' and '%'
// in a folder name are part of the path and not of the URI.
func fileURI(path string, q url.Values) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: q.Encode()}
	if filepath.VolumeName(abs) != "" {
		u.Path = "/" + u.Path // file:///C:/...
	}
	return u.String(), nil
}

// Open opens the store at path, making it when it does not exist (mode
// 0600). It stops with ErrNewerFormat for a file from a newer komando.
func Open(ctx context.Context, path string, key *sealrow.Key) (*DB, error) {
	if key == nil {
		return nil, errors.New("sealdb: no key")
	}
	// make the file with 0600 before SQLite does, so it is never readable
	// by others, not even for a moment
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	// a file that was already there keeps no wider mode than 0600
	err = f.Chmod(0o600)
	f.Close()
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	for _, p := range []string{
		"busy_timeout(" + strconv.Itoa(int(BusyTimeout/time.Millisecond)) + ")",
		"journal_mode(DELETE)",
		"synchronous(FULL)",
		"fullfsync(ON)",
		"foreign_keys(ON)",
		// a deleted record, or one sealed again under a new key, is
		// overwritten with zeros, not left in free space where the old
		// key (a leaked key file, the reason for a new one) opens it
		"secure_delete(ON)",
	} {
		q.Add("_pragma", p)
	}
	dsn, err := fileURI(path, q)
	if err != nil {
		return nil, err
	}
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// one connection per process: transactions are begun by hand on it, and
	// SQLite allows one writer anyway
	sdb.SetMaxOpenConns(1)
	d := &DB{db: sdb, key: key}
	if err := d.init(ctx); err != nil {
		sdb.Close()
		return nil, err
	}
	d.opened = true
	return d, nil
}

func (d *DB) init(ctx context.Context) error {
	// a store made already is checked in a read step, so opening it never
	// waits for, or holds up, another process's write
	ready := false
	err := d.run(ctx, false, func(tx *Tx) error {
		var n int
		if err := tx.c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('meta','records','audit')`).Scan(&n); err != nil || n < 3 {
			return err
		}
		var v string
		if err := tx.c.QueryRowContext(ctx, `SELECT v FROM meta WHERE k='format'`).Scan(&v); err != nil {
			return nil // made, but not finished: the write step below does it
		}
		ready = true
		return d.checkOpened(tx, v)
	})
	if err != nil || ready {
		return err
	}
	return d.run(ctx, true, func(tx *Tx) error {
		if _, err := tx.c.ExecContext(ctx, schema); err != nil {
			return err
		}
		var v string
		err := tx.c.QueryRowContext(ctx, `SELECT v FROM meta WHERE k='format'`).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) {
			if _, err = tx.c.ExecContext(ctx, `INSERT INTO meta(k,v) VALUES('format',?)`, strconv.Itoa(Format)); err != nil {
				return err
			}
			_, err = tx.Put(keycheckType, keycheckID, []byte("komando"))
			return err
		}
		if err != nil {
			return err
		}
		return d.checkOpened(tx, v)
	})
}

// checkOpened checks an existing store: its format, and that the key
// opens it.
func (d *DB) checkOpened(tx *Tx, v string) error {
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("sealdb: format %q is not a number", v)
	}
	if n > Format {
		return ErrNewerFormat
	}
	if _, err := tx.Get(keycheckID); err != nil {
		if errors.Is(err, sealrow.ErrOpen) {
			return ErrWrongKey
		}
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("record %s: %w", keycheckID, ErrTampered)
		}
		return err
	}
	return nil
}

// Peek reads the readable settings of the store at path (format, key mode,
// salt) without a key and without making the file. A missing file is
// os.ErrNotExist.
func Peek(ctx context.Context, path string) (map[string]string, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "busy_timeout("+strconv.Itoa(int(BusyTimeout/time.Millisecond))+")")
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

// Close closes the store.
func (d *DB) Close() error { return d.db.Close() }

// View runs fn in a read step: it sees one consistent store.
func (d *DB) View(ctx context.Context, fn func(*Tx) error) error {
	return d.run(ctx, false, fn)
}

// Update runs fn in a write step, which holds the write lock from its
// start, so a read, check and write inside fn (a unique name) cannot race
// another process. A non-nil error from fn undoes every change.
func (d *DB) Update(ctx context.Context, fn func(*Tx) error) error {
	return d.run(ctx, true, fn)
}

func (d *DB) run(ctx context.Context, write bool, fn func(*Tx) error) (err error) {
	if write && d.NoWrites != nil {
		return d.NoWrites
	}
	release, err := d.enter()
	if errors.Is(err, ErrNested) {
		return d.nested(write, fn)
	}
	if err != nil {
		return err
	}
	defer release()
	c, err := d.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	begin := "BEGIN DEFERRED"
	if write {
		begin = "BEGIN IMMEDIATE"
	}
	if _, err := c.ExecContext(ctx, begin); err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			// a panic or an error: undo; context.Background so a cancelled
			// ctx cannot leave the lock held
			if _, rerr := c.ExecContext(context.Background(), "ROLLBACK"); rerr != nil {
				// a connection still inside a step would fail every later
				// BEGIN: throw it away
				_ = c.Raw(func(any) error { return driver.ErrBadConn })
			}
		}
	}()
	tx := &Tx{ctx: ctx, c: c, key: d.key, write: write, ix: &ixState{}}
	if d.opened {
		if err := tx.checkKey(); err != nil {
			return err
		}
	}
	d.cur = tx
	defer func() { d.cur = nil }()
	if err := fn(tx); err != nil {
		return err
	}
	var gen uint64
	if tx.changed {
		if gen, err = tx.bumpGeneration(); err != nil {
			return err
		}
	}
	if _, err := c.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	done = true
	if gen > 0 && d.OnGeneration != nil {
		d.OnGeneration(gen)
	}
	return nil
}

// nested runs fn inside the step this goroutine is already running.
func (d *DB) nested(write bool, fn func(*Tx) error) error {
	outer := d.cur
	if outer == nil {
		return ErrNested
	}
	if !write {
		// a read sees the outer step's changes so far
		return fn(&Tx{ctx: outer.ctx, c: outer.c, key: outer.key, write: false, ix: outer.ix})
	}
	if !outer.write {
		return fmt.Errorf("%w: a change inside a read step", ErrNested)
	}
	d.depth++
	sp := "sp" + strconv.Itoa(d.depth)
	defer func() { d.depth-- }()
	if _, err := outer.c.ExecContext(outer.ctx, "SAVEPOINT "+sp); err != nil {
		return err
	}
	ok := false
	// the audit head and the change mark go back with the savepoint
	head, changed := outer.ix.head, outer.changed
	defer func() {
		if !ok {
			outer.ix.head, outer.changed = head, changed
			_, _ = outer.c.ExecContext(context.Background(), "ROLLBACK TO "+sp)
			_, _ = outer.c.ExecContext(context.Background(), "RELEASE "+sp)
		}
	}()
	if err := fn(outer); err != nil {
		return err
	}
	if _, err := outer.c.ExecContext(outer.ctx, "RELEASE "+sp); err != nil {
		return err
	}
	ok = true
	return nil
}

// enter waits for this process's turn at the store. A goroutine that is
// already inside a step gets ErrNested instead of waiting for itself.
func (d *DB) enter() (release func(), err error) {
	me := goid()
	if !d.mu.TryLock() {
		if d.holder.Load() == me {
			return nil, ErrNested
		}
		d.mu.Lock()
	}
	d.holder.Store(me)
	return func() { d.holder.Store(0); d.mu.Unlock() }, nil
}

// goid is the running goroutine's number, from the first line of its
// stack ("goroutine 7 [running]:"). Only used to tell a nested call apart.
func goid() uint64 {
	var buf [64]byte
	b := buf[:runtime.Stack(buf[:], false)]
	b, _ = bytes.CutPrefix(b, []byte("goroutine "))
	if i := bytes.IndexByte(b, ' '); i > 0 {
		b = b[:i]
	}
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

// Backup writes a consistent copy of the store to dst, which must not
// exist. A plain copy of the file taken during a write may be broken.
func (d *DB) Backup(ctx context.Context, dst string) error {
	release, err := d.enter()
	if err != nil {
		return err
	}
	defer release()
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("sealdb: %s already exists", dst)
	}
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	// VACUUM INTO refuses a non-empty file; an empty one made with 0600
	// keeps the copy private
	uri, err := fileURI(dst, nil)
	if err == nil {
		_, err = d.db.ExecContext(ctx, `VACUUM INTO ?`, uri)
	}
	if err == nil {
		err = syncFile(dst)
	}
	if err != nil {
		os.Remove(dst)
	}
	return err
}

// syncFile flushes path and its folder to disk; VACUUM INTO does not take
// the store's sync settings.
func syncFile(path string) error {
	for _, p := range []string{path, filepath.Dir(path)} {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		err = fullSync(f)
		f.Close()
		// a folder cannot be synced on some systems (Windows)
		if err != nil && p == path {
			return err
		}
	}
	return nil
}

// Record is one record, opened.
type Record struct {
	ID      string
	Type    string
	Version uint64
	MTime   time.Time
	Deleted bool
	Data    []byte
}

// AuditRow is one audit entry, opened.
type AuditRow struct {
	Seq  int64
	Time time.Time
	Data []byte
}

// Tx is one read or write step.
type Tx struct {
	ctx     context.Context
	c       *sql.Conn
	key     *sealrow.Key
	write   bool
	changed bool // a record or audit entry was written: the generation goes up
	ix      *ixState
}

// The sealed content of a record starts with its deletion marker and change
// time, so editing those readable columns is caught on open.
const headLen = 9

func head(del bool, mtime int64, data []byte) []byte {
	b := make([]byte, headLen, headLen+len(data))
	if del {
		b[0] = 1
	}
	binary.BigEndian.PutUint64(b[1:], uint64(mtime))
	return append(b, data...)
}

func (t *Tx) open(id, typ string, ver uint64, mtime int64, del int, sealed []byte) (Record, error) {
	plain, err := t.key.Open(sealrow.Row{ID: id, Type: typ, Version: ver}, sealed)
	if err != nil {
		return Record{}, fmt.Errorf("record %s: %w", id, err)
	}
	if len(plain) < headLen || (plain[0] != 0) != (del != 0) || int64(binary.BigEndian.Uint64(plain[1:])) != mtime {
		return Record{}, fmt.Errorf("record %s: %w", id, ErrTampered)
	}
	return Record{ID: id, Type: typ, Version: ver, MTime: time.Unix(0, mtime), Deleted: del != 0, Data: plain[headLen:]}, nil
}

// Get returns the record with id, deleted or not.
func (t *Tx) Get(id string) (Record, error) {
	r, err := t.rawGet(id)
	if errors.Is(err, ErrNotFound) {
		if cerr := t.checkRow(id, 0, false); cerr != nil {
			return Record{}, cerr
		}
		return r, err
	}
	if err != nil {
		return Record{}, err
	}
	if err := t.checkRow(id, r.Version, true); err != nil {
		return Record{}, err
	}
	return r, nil
}

// rawGet reads and opens a record without asking the index.
func (t *Tx) rawGet(id string) (Record, error) {
	var (
		typ    string
		ver    uint64
		mtime  int64
		del    int
		sealed []byte
	)
	err := t.c.QueryRowContext(t.ctx, `SELECT type,version,mtime,deleted,data FROM records WHERE id=?`, id).
		Scan(&typ, &ver, &mtime, &del, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	return t.open(id, typ, ver, mtime, del, sealed)
}

// List returns every record of type typ that is not deleted, oldest change
// first.
func (t *Tx) List(typ string) ([]Record, error) {
	rows, err := t.c.QueryContext(t.ctx, `SELECT id,version,mtime,data FROM records WHERE type=? AND deleted=0 ORDER BY mtime,id`, typ)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	seen := map[string]bool{}
	for rows.Next() {
		var (
			id     string
			ver    uint64
			mtime  int64
			sealed []byte
		)
		if err := rows.Scan(&id, &ver, &mtime, &sealed); err != nil {
			return nil, err
		}
		r, err := t.open(id, typ, ver, mtime, 0, sealed)
		if err != nil {
			return nil, err
		}
		if err := t.checkRow(id, ver, true); err != nil {
			return nil, err
		}
		seen[id] = true
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err := t.checkList(typ, seen); err != nil {
		return nil, err
	}
	return out, nil
}

// Put writes data as record id of type typ, at the next version. An empty
// id makes a new record with a random ID. A record keeps its type.
func (t *Tx) Put(typ, id string, data []byte) (Record, error) {
	if !t.write {
		return Record{}, ErrReadOnly
	}
	var ver uint64
	if id == "" {
		var err error
		if id, err = sealrow.NewID(); err != nil {
			return Record{}, err
		}
	} else {
		var old string
		err := t.c.QueryRowContext(t.ctx, `SELECT type,version FROM records WHERE id=?`, id).Scan(&old, &ver)
		if err == nil || errors.Is(err, sql.ErrNoRows) {
			if cerr := t.checkRow(id, ver, err == nil); cerr != nil {
				return Record{}, cerr
			}
		}
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return Record{}, err
		case old != typ:
			return Record{}, fmt.Errorf("sealdb: record %s is a %s, not a %s", id, old, typ)
		}
	}
	if err := t.touch(id); err != nil {
		return Record{}, err
	}
	return t.write1(id, typ, ver+1, false, data)
}

// Delete marks record id deleted and drops its content. The ID and the
// marker stay, so a later sync can tell a deletion from a record never
// seen. Deleting a missing record is ErrNotFound.
func (t *Tx) Delete(id string) error {
	if !t.write {
		return ErrReadOnly
	}
	var (
		typ string
		ver uint64
	)
	err := t.c.QueryRowContext(t.ctx, `SELECT type,version FROM records WHERE id=?`, id).Scan(&typ, &ver)
	if errors.Is(err, sql.ErrNoRows) {
		if cerr := t.checkRow(id, 0, false); cerr != nil {
			return cerr
		}
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := t.checkRow(id, ver, true); err != nil {
		return err
	}
	if err := t.touch(id); err != nil {
		return err
	}
	_, err = t.write1(id, typ, ver+1, true, nil)
	return err
}

func (t *Tx) write1(id, typ string, ver uint64, del bool, data []byte) (Record, error) {
	now := time.Now()
	sealed, err := t.key.Seal(sealrow.Row{ID: id, Type: typ, Version: ver}, head(del, now.UnixNano(), data))
	if err != nil {
		return Record{}, err
	}
	d := 0
	if del {
		d = 1
	}
	_, err = t.c.ExecContext(t.ctx, `INSERT INTO records(id,type,version,mtime,deleted,data) VALUES(?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET version=excluded.version, mtime=excluded.mtime, deleted=excluded.deleted, data=excluded.data`,
		id, typ, ver, now.UnixNano(), d, sealed)
	if err != nil {
		return Record{}, err
	}
	return Record{ID: id, Type: typ, Version: ver, MTime: time.Unix(0, now.UnixNano()), Deleted: del, Data: data}, nil
}

// Meta returns one readable setting, "" when it is not set.
func (t *Tx) Meta(k string) (string, error) {
	var v string
	err := t.c.QueryRowContext(t.ctx, `SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetMeta sets one readable setting. Readable means anyone with the file
// sees it: never a name, a secret or a host.
func (t *Tx) SetMeta(k, v string) error {
	if !t.write {
		return ErrReadOnly
	}
	if k == "format" {
		return errors.New("sealdb: the format is set by the store itself")
	}
	_, err := t.c.ExecContext(t.ctx, `INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

// checkKey stops a step whose key no longer opens the store's keycheck
// record: another process changed the key after this handle was opened.
func (t *Tx) checkKey() error {
	_, err := t.rawGet(keycheckID)
	switch {
	case err == nil, errors.Is(err, ErrNotFound): // not made yet
		return nil
	case errors.Is(err, sealrow.ErrOpen):
		return ErrKeyChanged
	}
	return err
}

// AuditLast is the number of the newest audit entry, 0 when there is none.
func (t *Tx) AuditLast() (int64, error) {
	var n int64
	err := t.c.QueryRowContext(t.ctx, `SELECT COALESCE(MAX(seq),0) FROM audit`).Scan(&n)
	return n, err
}
