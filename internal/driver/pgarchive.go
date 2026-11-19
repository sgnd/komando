package driver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// A pg_dump custom archive ("PGDMP") holds its SQL in a table of contents
// at the start: each entry has the statement that makes the object (defn)
// and, for table data, the COPY that loads it. pg_restore sends those to
// the server. CheckRestoreArchive reads that table (not the data, which is
// rows) and checks the SQL as CheckRestore checks a plain dump, so what an
// archive does beyond writing data is named in the approval as well.
//
// The layout follows pg_dump's pg_backup_archiver.c, archive versions
// 1.12 (PostgreSQL 9.5) to 1.16 (PostgreSQL 17).

// pgArchiveMaxStr is the longest string komando reads from an archive's
// table of contents; a longer one counts as a damaged archive.
const pgArchiveMaxStr = 64 << 20

type pgArchive struct {
	r       *bufio.Reader
	version int // major<<16 | minor<<8 | rev
	intSize int
	offSize int
}

func pgVersion(major, minor, rev int) int { return major<<16 | minor<<8 | rev }

var errPGArchive = errors.New("not a pg_dump archive komando can read")

func (a *pgArchive) byte() (int, error) {
	b, err := a.r.ReadByte()
	return int(b), err
}

// readInt is pg_dump's ReadInt: a sign byte, then intSize bytes, lowest first.
func (a *pgArchive) readInt() (int64, error) {
	sign, err := a.byte()
	if err != nil {
		return 0, err
	}
	var v uint64
	for i := 0; i < a.intSize; i++ {
		b, err := a.byte()
		if err != nil {
			return 0, err
		}
		if i < 8 {
			v |= uint64(b) << (8 * i)
		}
	}
	if v > 1<<62 {
		return 0, errPGArchive
	}
	if sign != 0 {
		return -int64(v), nil
	}
	return int64(v), nil
}

// readStr is pg_dump's ReadStr: a length (-1 for none), then the bytes.
func (a *pgArchive) readStr() (string, bool, error) {
	n, err := a.readInt()
	if err != nil {
		return "", false, err
	}
	if n < 0 {
		return "", false, nil
	}
	if n > pgArchiveMaxStr {
		return "", false, errPGArchive
	}
	// grown with the bytes that arrive, so a damaged length does not
	// allocate 64 MiB up front
	var b strings.Builder
	if _, err := io.CopyN(&b, a.r, n); err != nil {
		return "", false, err
	}
	return b.String(), true, nil
}

func (a *pgArchive) str() (string, error) {
	s, _, err := a.readStr()
	return s, err
}

// header reads the archive's head up to its table of contents.
func (a *pgArchive) header() error {
	magic := make([]byte, 5)
	if _, err := io.ReadFull(a.r, magic); err != nil || string(magic) != "PGDMP" {
		return errPGArchive
	}
	var v [6]int
	for i := range v {
		b, err := a.byte()
		if err != nil {
			return err
		}
		v[i] = b
	}
	a.version, a.intSize, a.offSize = pgVersion(v[0], v[1], v[2]), v[3], v[4]
	if a.version < pgVersion(1, 12, 0) || a.version > pgVersion(1, 16, 0) || a.intSize < 1 || a.intSize > 8 || a.offSize < 1 || a.offSize > 8 || v[5] != 1 {
		return fmt.Errorf("%w (version %d.%d, format %d)", errPGArchive, v[0], v[1], v[5])
	}
	if a.version >= pgVersion(1, 15, 0) {
		if _, err := a.byte(); err != nil { // compression algorithm
			return err
		}
	} else if _, err := a.readInt(); err != nil { // compression level
		return err
	}
	for i := 0; i < 7; i++ { // when it was made
		if _, err := a.readInt(); err != nil {
			return err
		}
	}
	for i := 0; i < 3; i++ { // database name, server and pg_dump versions
		if _, err := a.str(); err != nil {
			return err
		}
	}
	return nil
}

// pgTocEntry is what an entry sends to the server.
type pgTocEntry struct {
	hasData                    bool
	desc, defn, drop, copyStmt string
}

// entry reads one entry of the table of contents.
func (a *pgArchive) entry() (pgTocEntry, error) {
	var e pgTocEntry
	ints := func(n int) error {
		for i := 0; i < n; i++ {
			if _, err := a.readInt(); err != nil {
				return err
			}
		}
		return nil
	}
	strs := func(n int) error {
		for i := 0; i < n; i++ {
			if _, err := a.str(); err != nil {
				return err
			}
		}
		return nil
	}
	if err := ints(1); err != nil { // dump id
		return e, err
	}
	had, err := a.readInt()
	if err != nil {
		return e, err
	}
	e.hasData = had != 0
	if err := strs(3); err != nil { // table oid, oid, tag
		return e, err
	}
	if e.desc, err = a.str(); err != nil {
		return e, err
	}
	if err := ints(1); err != nil { // section
		return e, err
	}
	if e.defn, err = a.str(); err != nil {
		return e, err
	}
	// the drop statement: pg_restore copies part of it into ALTER ...
	// OWNER TO, so it reaches the server even without --clean
	if e.drop, err = a.str(); err != nil {
		return e, err
	}
	if e.copyStmt, err = a.str(); err != nil {
		return e, err
	}
	if err := strs(2); err != nil { // schema, tablespace
		return e, err
	}
	if a.version >= pgVersion(1, 14, 0) {
		if err := strs(1); err != nil { // table access method
			return e, err
		}
	}
	if a.version >= pgVersion(1, 16, 0) {
		if err := ints(1); err != nil { // relkind
			return e, err
		}
	}
	if err := strs(2); err != nil { // owner, with oids
		return e, err
	}
	for { // the ids it depends on, to a missing string
		_, ok, err := a.readStr()
		if err != nil {
			return e, err
		}
		if !ok {
			break
		}
	}
	// the custom format's data place (ReadOffset): a state byte, then
	// offSize bytes
	_, err = io.ReadFull(a.r, make([]byte, 1+a.offSize))
	return e, err
}

// pgArchiveSQLMax is the most SQL komando collects from an archive's
// table of contents; a larger one is refused.
const pgArchiveSQLMax = 256 << 20

// pgArchiveSQL reads an archive's table of contents and returns its SQL as
// pg_restore sends it, each COPY followed by the end of its (left out)
// data, and why part of it is SQL komando did not read ("" when none).
func pgArchiveSQL(r io.Reader) (sql, unread string, err error) {
	a := &pgArchive{r: bufio.NewReader(r)}
	if err := a.header(); err != nil {
		return "", "", err
	}
	n, err := a.readInt()
	if err != nil {
		return "", "", err
	}
	if n < 0 || n > 10_000_000 {
		return "", "", errPGArchive
	}
	var b strings.Builder
	for i := int64(0); i < n; i++ {
		e, err := a.entry()
		if err != nil {
			return "", "", fmt.Errorf("entry %d of %d: %w", i+1, n, err)
		}
		for _, stmt := range []string{e.defn, e.drop} {
			if stmt != "" {
				b.WriteString(stmt)
				b.WriteString("\n")
			}
		}
		switch {
		case e.copyStmt != "":
			if strings.Contains(strings.TrimRight(e.copyStmt, "\n"), "\n") || !IsCopyStdin(strings.ToUpper(strings.TrimSuffix(strings.TrimSpace(e.copyStmt), ";"))) {
				return "", "", fmt.Errorf("entry %d: a COPY that is not one COPY ... FROM stdin", i+1)
			}
			b.WriteString(e.copyStmt)
			b.WriteString("\n\\.\n")
		case e.hasData && unread == "" && !strings.HasPrefix(e.desc, "BLOB"):
			// table data with no COPY is SQL (pg_dump --inserts), kept
			// in the data part komando does not read
			unread = "the archive keeps " + strings.ToLower(e.desc) + " as SQL statements (pg_dump --inserts), which komando does not read"
		}
		if b.Len() > pgArchiveSQLMax {
			return "", "", fmt.Errorf("more than %d MiB of SQL", pgArchiveSQLMax>>20)
		}
	}
	return b.String(), unread, nil
}

// ErrBadArchive is what CheckRestoreArchive returns for an archive komando
// cannot read.
var ErrBadArchive = errors.New("komando cannot read this pg_dump archive's table of contents")

// CheckRestoreArchive checks a pg_dump custom archive as CheckRestore checks
// a plain dump. An archive komando cannot read (another version, cut or
// damaged) is refused with ErrBadArchive: approving SQL nobody could look
// at would leave the check to pg_restore.
func CheckRestoreArchive(r io.Reader) (Verdict, error) {
	sql, unread, err := pgArchiveSQL(r)
	if err != nil {
		return Verdict{}, fmt.Errorf("%w: %v", ErrBadArchive, err)
	}
	v, err := CheckRestore("postgres", strings.NewReader(sql))
	if err != nil || unread == "" {
		return v, err
	}
	return opaqueArchive(v, unread), nil
}

// opaqueArchive adds sql-opaque to v with why as its reason.
func opaqueArchive(v Verdict, why string) Verdict {
	v.Risk = RiskDestructive
	v.RuleIDs = append(v.RuleIDs, "sql-opaque")
	v.Reasons = append(v.Reasons, why)
	return v
}
